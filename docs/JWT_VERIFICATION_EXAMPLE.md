# JWT Verification для других микросервисов

## Как это работает

В проекте используется **асимметричная криптография (RSA)** с алгоритмом **RS256**:
- **Приватный ключ** - хранится только в auth service, используется для **подписи** токенов
- **Публичный ключ** - доступен всем микросервисам, используется для **верификации** токенов

Это означает, что другие сервисы могут проверять подлинность токенов **без доступа к приватному ключу**.

## ⚠️ Важно: Безопасность публичного ключа

**Публичный ключ МОЖЕТ быть публичным** - это нормально и безопасно! Публичный ключ в асимметричной криптографии специально предназначен для публичного распространения. Его безопасность основана на том, что приватный ключ остается секретным.

Однако для **внутренней микросервисной коммуникации** рекомендуется использовать **gRPC** вместо HTTP:
- ✅ Лучшая производительность
- ✅ Типизация через protobuf
- ✅ Встроенная поддержка streaming
- ✅ Лучшая безопасность для внутренней сети

## Получение публичного ключа

### Вариант 1: gRPC (рекомендуется для внутренних сервисов)

Для внутренней микросервисной коммуникации используйте gRPC:

```go
// Подключение к auth service через gRPC
conn, err := grpc.Dial("auth-service:9000", grpc.WithInsecure())
authClient := auth.NewAuthServiceClient(conn)

// Получение публичного ключа
resp, err := authClient.GetPublicKey(context.Background(), &auth.GetPublicKeyRequest{})
publicKeyPEM := resp.PublicKeyPem
```

**Преимущества:**
- Типобезопасность через protobuf
- Высокая производительность
- Подходит для внутренней сети

### Вариант 2: HTTP Endpoint (для публичного API)

Auth service предоставляет публичный ключ через endpoint:

```bash
# Стандартный JWKS endpoint
GET http://auth-service:8000/auth/.well-known/jwks.json

# Альтернативный endpoint
GET http://auth-service:8000/auth/public-key
```

**Ответ:**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "key": "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA..."
    }
  ],
  "public_key_pem": "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA..."
}
```

### Вариант 3: Файл (для статической конфигурации)

Публичный ключ сохраняется в файл `./keys/jwt_public.pem` при первом запуске auth service.

## Рекомендации по выбору метода

| Метод | Когда использовать |
|-------|-------------------|
| **gRPC** | Внутренняя микросервисная коммуникация, высокая производительность |
| **HTTP** | Публичный API, интеграция с внешними сервисами, простота |
| **Файл** | Статическая конфигурация, Kubernetes ConfigMap/Secret |

**Для микросервисной архитектуры:** используйте gRPC для внутренних сервисов, HTTP для публичного API.

## Пример верификации токена в Go

```go
package main

import (
    "crypto/rsa"
    "crypto/x509"
    "encoding/pem"
    "fmt"
    "io"
    "net/http"
    "time"

    "github.com/golang-jwt/jwt/v5"
)

type Claims struct {
    UserID string `json:"user_id"`
    jwt.RegisteredClaims
}

type JWKSService struct {
    publicKey *rsa.PublicKey
    authURL   string
}

// NewJWKSService создает сервис для верификации JWT токенов
func NewJWKSService(authURL string) (*JWKSService, error) {
    service := &JWKSService{
        authURL: authURL,
    }
    
    // Загружаем публичный ключ при инициализации
    if err := service.loadPublicKey(); err != nil {
        return nil, fmt.Errorf("failed to load public key: %w", err)
    }
    
    return service, nil
}

// loadPublicKey загружает публичный ключ с auth service
func (j *JWKSService) loadPublicKey() error {
    // Получаем публичный ключ через HTTP
    resp, err := http.Get(j.authURL + "/auth/.well-known/jwks.json")
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return err
    }

    // Парсим JSON ответ
    var jwks struct {
        PublicKeyPEM string `json:"public_key_pem"`
    }
    if err := json.Unmarshal(body, &jwks); err != nil {
        return err
    }

    // Парсим PEM формат
    block, _ := pem.Decode([]byte(jwks.PublicKeyPEM))
    if block == nil {
        return fmt.Errorf("failed to decode PEM")
    }

    // Парсим RSA публичный ключ
    pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
    if err != nil {
        return err
    }

    j.publicKey = pub
    return nil
}

// VerifyToken верифицирует JWT токен
func (j *JWKSService) VerifyToken(tokenString string) (*Claims, error) {
    token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
        // Проверяем алгоритм
        if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return j.publicKey, nil
    })

    if err != nil {
        return nil, err
    }

    if claims, ok := token.Claims.(*Claims); ok && token.Valid {
        return claims, nil
    }

    return nil, fmt.Errorf("invalid token")
}

// Пример использования в middleware
func AuthMiddleware(jwks *JWKSService) fiber.Handler {
    return func(c *fiber.Ctx) error {
        // Получаем токен из заголовка
        authHeader := c.Get("Authorization")
        if authHeader == "" {
            return c.Status(401).JSON(fiber.Map{
                "error": "missing_authorization_header",
            })
        }

        // Извлекаем токен (Bearer <token>)
        token := authHeader
        if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
            token = authHeader[7:]
        }

        // Верифицируем токен
        claims, err := jwks.VerifyToken(token)
        if err != nil {
            return c.Status(401).JSON(fiber.Map{
                "error": "invalid_token",
                "message": err.Error(),
            })
        }

        // Сохраняем user_id в контексте для использования в handlers
        c.Locals("user_id", claims.UserID)
        
        return c.Next()
    }
}

// Пример использования
func main() {
    app := fiber.New()
    
    // Инициализируем JWKS сервис
    jwks, err := NewJWKSService("http://auth-service:8000")
    if err != nil {
        panic(err)
    }
    
    // Применяем middleware
    app.Use(AuthMiddleware(jwks))
    
    // Защищенный endpoint
    app.Get("/protected", func(c *fiber.Ctx) error {
        userID := c.Locals("user_id")
        return c.JSON(fiber.Map{
            "message": "Access granted",
            "user_id": userID,
        })
    })
    
    app.Listen(":8080")
}
```

## Пример верификации в других языках

### Node.js (Express)

```javascript
const express = require('express');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const crypto = require('crypto');

let publicKey = null;

// Загружаем публичный ключ
async function loadPublicKey() {
    const response = await axios.get('http://auth-service:8000/auth/.well-known/jwks.json');
    publicKey = response.data.public_key_pem;
}

// Middleware для верификации
async function verifyToken(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'missing_authorization_header' });
    }

    const token = authHeader.substring(7);
    
    try {
        const decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ error: 'invalid_token', message: err.message });
    }
}

// Инициализация
loadPublicKey().then(() => {
    const app = express();
    app.use(verifyToken);
    
    app.get('/protected', (req, res) => {
        res.json({ message: 'Access granted', user_id: req.user.user_id });
    });
    
    app.listen(8080);
});
```

### Python (FastAPI)

```python
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
import requests
from cryptography.hazmat.primitives import serialization

security = HTTPBearer()
public_key = None

def load_public_key():
    global public_key
    response = requests.get("http://auth-service:8000/auth/.well-known/jwks.json")
    pem_key = response.json()["public_key_pem"]
    public_key = serialization.load_pem_public_key(pem_key.encode())

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(
            credentials.credentials,
            public_key,
            algorithms=["RS256"]
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

app = FastAPI()

@app.on_event("startup")
async def startup_event():
    load_public_key()

@app.get("/protected")
async def protected_route(user: dict = Depends(verify_token)):
    return {"message": "Access granted", "user_id": user["user_id"]}
```

## Обновление ключа

Если ключи обновляются в auth service, другие сервисы должны периодически обновлять публичный ключ. Рекомендуется:

1. **Кэшировать ключ** с TTL (например, 1 час)
2. **Обновлять автоматически** при ошибке верификации
3. **Использовать версионирование** ключей (kid в JWKS)

## Безопасность

✅ **Правильно:**
- Публичный ключ можно безопасно передавать между сервисами
- Приватный ключ хранится только в auth service
- Каждый сервис верифицирует токены независимо

❌ **Неправильно:**
- Использовать симметричный алгоритм (HS256) с общим секретом
- Передавать приватный ключ другим сервисам
- Доверять токенам без верификации

## Дополнительные улучшения

1. **JWKS с версионированием** - добавить `kid` (key ID) для ротации ключей
2. **Кэширование** - кэшировать публичный ключ в других сервисах
3. **Health check** - проверять доступность auth service
4. **Retry logic** - автоматически обновлять ключ при ошибках

