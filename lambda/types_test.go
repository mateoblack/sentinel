package lambda

import (
	"testing"

	"github.com/aws/aws-lambda-go/events"
)

func TestExtractCallerIdentity(t *testing.T) {
	tests := []struct {
		name    string
		req     events.APIGatewayV2HTTPRequest
		want    *CallerIdentity
		wantErr bool
	}{
		{
			name: "valid IAM context",
			req: events.APIGatewayV2HTTPRequest{
				RequestContext: events.APIGatewayV2HTTPRequestContext{
					Authorizer: &events.APIGatewayV2HTTPRequestContextAuthorizerDescription{
						IAM: &events.APIGatewayV2HTTPRequestContextAuthorizerIAMDescription{
							AccountID: "123456789012",
							UserARN:   "arn:aws:iam::123456789012:user/testuser",
							UserID:    "AIDAEXAMPLE",
							AccessKey: "AKIAEXAMPLE",
						},
					},
				},
			},
			want: &CallerIdentity{
				AccountID: "123456789012",
				UserARN:   "arn:aws:iam::123456789012:user/testuser",
				UserID:    "AIDAEXAMPLE",
				AccessKey: "AKIAEXAMPLE",
			},
			wantErr: false,
		},
		{
			name: "missing IAM authorizer",
			req: events.APIGatewayV2HTTPRequest{
				RequestContext: events.APIGatewayV2HTTPRequestContext{
					Authorizer: nil,
				},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "nil IAM field",
			req: events.APIGatewayV2HTTPRequest{
				RequestContext: events.APIGatewayV2HTTPRequestContext{
					Authorizer: &events.APIGatewayV2HTTPRequestContextAuthorizerDescription{
						IAM: nil,
					},
				},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "missing required AccountID",
			req: events.APIGatewayV2HTTPRequest{
				RequestContext: events.APIGatewayV2HTTPRequestContext{
					Authorizer: &events.APIGatewayV2HTTPRequestContextAuthorizerDescription{
						IAM: &events.APIGatewayV2HTTPRequestContextAuthorizerIAMDescription{
							UserARN: "arn:aws:iam::123456789012:user/testuser",
						},
					},
				},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "with PrincipalOrgID",
			req: events.APIGatewayV2HTTPRequest{
				RequestContext: events.APIGatewayV2HTTPRequestContext{
					Authorizer: &events.APIGatewayV2HTTPRequestContextAuthorizerDescription{
						IAM: &events.APIGatewayV2HTTPRequestContextAuthorizerIAMDescription{
							AccountID:      "123456789012",
							UserARN:        "arn:aws:iam::123456789012:user/testuser",
							UserID:         "AIDAEXAMPLE",
							PrincipalOrgID: "o-exampleorgid",
						},
					},
				},
			},
			want: &CallerIdentity{
				AccountID:      "123456789012",
				UserARN:        "arn:aws:iam::123456789012:user/testuser",
				UserID:         "AIDAEXAMPLE",
				PrincipalOrgID: "o-exampleorgid",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractCallerIdentity(tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractCallerIdentity() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if got.AccountID != tt.want.AccountID ||
				got.UserARN != tt.want.UserARN ||
				got.UserID != tt.want.UserID ||
				got.AccessKey != tt.want.AccessKey ||
				got.PrincipalOrgID != tt.want.PrincipalOrgID {
				t.Errorf("ExtractCallerIdentity() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
