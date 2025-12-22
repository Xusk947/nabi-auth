package grpc

import (
	"context"
	"fmt"
	"net"

	pb "nabi-auth/api/proto"
	"nabi-auth/internal/pkg/config"
	"nabi-auth/internal/pkg/jwt"

	"go.uber.org/fx"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

type AuthGRPCServer struct {
	pb.UnimplementedAuthServiceServer
	jwtService *jwt.JWTService
	logger     *zap.Logger
}

func NewAuthGRPCServer(jwtService *jwt.JWTService, logger *zap.Logger) *AuthGRPCServer {
	return &AuthGRPCServer{
		jwtService: jwtService,
		logger:     logger,
	}
}

func (s *AuthGRPCServer) GetPublicKey(ctx context.Context, req *pb.GetPublicKeyRequest) (*pb.GetPublicKeyResponse, error) {
	publicKeyPEM, err := s.jwtService.GetPublicKeyPEM()
	if err != nil {
		s.logger.Error("Failed to get public key", zap.Error(err))
		return nil, err
	}

	return &pb.GetPublicKeyResponse{
		PublicKeyPem: string(publicKeyPEM),
		Algorithm:    "RS256",
		KeyId:        "default",
	}, nil
}

func (s *AuthGRPCServer) VerifyToken(ctx context.Context, req *pb.VerifyTokenRequest) (*pb.VerifyTokenResponse, error) {
	claims, err := s.jwtService.ValidateToken(req.Token)
	if err != nil {
		return &pb.VerifyTokenResponse{
			Valid: false,
			Error: err.Error(),
		}, nil
	}

	userIDBytes, err := claims.UserID.MarshalJSON()
	if err != nil {
		return &pb.VerifyTokenResponse{
			Valid: false,
			Error: "failed to marshal user_id",
		}, nil
	}

	return &pb.VerifyTokenResponse{
		Valid:     true,
		UserId:    string(userIDBytes),
		ExpiresAt: claims.RegisteredClaims.ExpiresAt.Unix(),
	}, nil
}

func StartGRPCServer(lc fx.Lifecycle, cfg *config.Config, authServer *AuthGRPCServer, logger *zap.Logger) error {
	lis, err := net.Listen("tcp", cfg.Server.GRPCHost)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", cfg.Server.GRPCHost, err)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterAuthServiceServer(grpcServer, authServer)

	lc.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			logger.Info("Starting gRPC server", zap.String("address", cfg.Server.GRPCHost))
			go func() {
				if err := grpcServer.Serve(lis); err != nil {
					logger.Fatal("Failed to serve gRPC", zap.Error(err))
				}
			}()
			return nil
		},
		OnStop: func(ctx context.Context) error {
			logger.Info("Stopping gRPC server")
			grpcServer.GracefulStop()
			return nil
		},
	})

	return nil
}

var Module = fx.Module(
	"grpc",
	fx.Provide(NewAuthGRPCServer),
	fx.Invoke(StartGRPCServer),
)
