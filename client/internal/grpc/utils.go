package grpc

import (
	"context"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

func retryingCall[Req, Res proto.Message](
	ctx context.Context,
	call func(ctx context.Context, req Req, opts ...grpc.CallOption) (Res, error),
	req Req,
	maxRetries int,
) (Res, error) {

	var result Res
	var err error
	for i := 0; i < maxRetries; i++ {
		result, err = call(ctx, req)
		if err == nil {
			return result, nil
		}
		time.Sleep(time.Millisecond * 100)
	}
	return result, err
}
