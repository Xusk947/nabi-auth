# gRPC Setup для Auth Service

## Обзор

Для внутренней микросервисной коммуникации используется gRPC вместо HTTP REST API. Это обеспечивает:
- ✅ Типобезопасность через Protocol Buffers
- ✅ Высокую производительность
- ✅ Лучшую безопасность для внутренней сети
- ✅ Поддержку streaming

## Архитектура

```
┌─────────────────┐         gRPC          ┌─────────────────┐
│  Auth Service   │ ◄───────────────────► │ Other Services  │
│  (gRPC Server)  │    Port 9000          │ (gRPC Clients)   │
└─────────────────┘                        └─────────────────┘
         │
         │ HTTP (для публичного API)
         ▼
┌─────────────────┐
│  Public API     │
│  (REST/HTTP)    │
└─────────────────┘
```

## Установка зависимостей

```bash
go get google.golang.org/grpc
go get google.golang.org/protobuf/cmd/protoc-gen-go
go get google.golang.org/grpc/cmd/protoc-gen-go-grpc
```

## Генерация кода из proto

```bash
# Установить protoc (если еще не установлен)
# Linux:
wget https://github.com/protocolbuffers/protobuf/releases/download/v25.1/protoc-25.1-linux-x86_64.zip
unzip protoc-25.1-linux-x86_64.zip -d /usr/local

# Генерация Go кода
protoc --go_out=. --go_opt=paths=source_relative \
       --go-grpc_out=. --go-grpc_opt=paths=source_relative \
       api/proto/auth.proto
```

## Реализация gRPC сервера

Создайте файл `internal/server/auth/grpc/server.go`:

```go
package grpc

import (
    "context"
    "nabi-auth/api/proto/auth"
    "nabi-auth/internal/pkg/jwt"
    "go.uber.org/zap"
)

type AuthGRPCServer struct {
    auth.UnimplementedAuthServiceServer
    jwtService *jwt.JWTService
    logger     *zap.Logger
}

func NewAuthGRPCServer(jwtService *jwt.JWTService, logger *zap.Logger) *AuthGRPCServer {
    return &AuthGRPCServer{
        jwtService: jwtService,
        logger:     logger,
    }
}

func (s *AuthGRPCServer) GetPublicKey(ctx context.Context, req *auth.GetPublicKeyRequest) (*auth.GetPublicKeyResponse, error) {
    publicKeyPEM, err := s.jwtService.GetPublicKeyPEM()
    if err != nil {
        s.logger.Error("Failed to get public key", zap.Error(err))
        return nil, err
    }

    return &auth.GetPublicKeyResponse{
        PublicKeyPem: string(publicKeyPEM),
        Algorithm:    "RS256",
        KeyId:        "1", // Можно использовать для версионирования ключей
    }, nil
}

func (s *AuthGRPCServer) VerifyToken(ctx context.Context, req *auth.VerifyTokenRequest) (*auth.VerifyTokenResponse, error) {
    claims, err := s.jwtService.ValidateToken(req.Token)
    if err != nil {
        return &auth.VerifyTokenResponse{
            Valid: false,
            Error:  err.Error(),
        }, nil
    }

    return &auth.VerifyTokenResponse{
        Valid:     true,
        UserId:    claims.UserID.String(),
        ExpiresAt: claims.ExpiresAt.Unix(),
    }, nil
}
```

## Запуск gRPC сервера

Добавьте в `internal/pkg/server/server.go`:

```go
import (
    "google.golang.org/grpc"
    "nabi-auth/internal/server/auth/grpc"
    authpb "nabi-auth/api/proto/auth"
)

func RunGRPCServer(lc fx.Lifecycle, jwtService *jwt.JWTService, log *zap.Logger, cfg *config.Config) {
    lc.Append(fx.Hook{
        OnStart: func(ctx context.Context) error {
            go func() {
                lis, err := net.Listen("tcp", ":9000")
                if err != nil {
                    log.Fatal("Failed to listen", zap.Error(err))
                }

                s := grpc.NewServer()
                authpb.RegisterAuthServiceServer(s, grpc.NewAuthGRPCServer(jwtService, log))

                log.Info("gRPC server listening on :9000")
                if err := s.Serve(lis); err != nil {
                    log.Fatal("Failed to serve", zap.Error(err))
                }
            }()
            return nil
        },
    })
}
```

## Использование в других микросервисах

### Go клиент

```go
package main

import (
    "context"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
    authpb "your-project/api/proto/auth"
)

func main() {
    // Подключение к auth service
    conn, err := grpc.Dial("auth-service:9000", grpc.WithTransportCredentials(insecure.NewCredentials()))
    if err != nil {
        panic(err)
    }
    defer conn.Close()

    client := authpb.NewAuthServiceClient(conn)

    // Получение публичного ключа
    resp, err := client.GetPublicKey(context.Background(), &authpb.GetPublicKeyRequest{})
    if err != nil {
        panic(err)
    }

    publicKeyPEM := resp.PublicKeyPem
    // Используйте ключ для верификации токенов
}
```

### Или верификация через gRPC

```go
// Вместо локальной верификации, можно использовать централизованную
verifyResp, err := client.VerifyToken(context.Background(), &authpb.VerifyTokenRequest{
    Token: tokenString,
})

if verifyResp.Valid {
    userID := verifyResp.UserId
    // Продолжить обработку запроса
}
```

## Docker Compose обновление

Добавьте gRPC порт в `docker-compose.yml`:

```yaml
app:
  ports:
    - "${APP_PORT:-8000}:8000"  # HTTP
    - "${GRPC_PORT:-9000}:9000" # gRPC
```

## Безопасность

1. **TLS для production**: Используйте `grpc.WithTransportCredentials(credentials.NewTLS(...))` вместо `insecure`
2. **mTLS**: Для взаимной аутентификации между сервисами
3. **Network policies**: Ограничьте доступ к gRPC порту только внутренними сервисами

## Преимущества gRPC vs HTTP

| Аспект | gRPC | HTTP REST |
|--------|------|-----------|
| Производительность | Выше (бинарный протокол) | Ниже (текстовый) |
| Типизация | Строгая (protobuf) | Слабая (JSON) |
| Streaming | Поддерживается | Ограниченно |
| Размер данных | Меньше | Больше |
| Кэширование | Сложнее | Проще |
| Публичный API | Не подходит | Идеально |

**Вывод:** Используйте gRPC для внутренних сервисов, HTTP для публичного API.

