package storage

import (
	"context"
	"errors"
	"fiber-di-server-template/internal/pkg/config"
	"net/http"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/aws"
	amazon "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	smithyendpoints "github.com/aws/smithy-go/endpoints"
	"go.uber.org/fx"
)

type customResolver struct {
	Url string
}

func (r *customResolver) ResolveEndpoint(ctx context.Context, params amazon.EndpointParameters) (smithyendpoints.Endpoint, error) {
	u, err := url.Parse(r.Url)
	if err != nil {
		return smithyendpoints.Endpoint{}, err
	}

	props := smithy.Properties{}
	return smithyendpoints.Endpoint{
		URI:        *u,
		Headers:    http.Header{},
		Properties: props,
	}, nil
}

func NewS3Client(cfg *config.Config) *amazon.Client {
	awsConfig := aws.Config{}

	c := amazon.NewFromConfig(awsConfig, func(options *amazon.Options) {
		options.EndpointResolverV2 = &customResolver{
			Url: cfg.S3.URL,
		}
		options.UsePathStyle = true
	})

	if c == nil {
		panic(errors.New("storage client is null"))
	}

	return c
}

var Module = fx.Module("storage",
	fx.Provide(NewS3Client),
)
