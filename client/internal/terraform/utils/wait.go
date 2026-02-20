package utils

import (
	"context"
	"fmt"
	"net"
	"time"

	"golang.org/x/sync/errgroup"
)

func WaitForPort(ctx context.Context, endpoints map[string]int32) error {
	result := make(chan error, 1)

	go doWaitForPort(ctx, result, endpoints)

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-result:
		return err
	}
}

func doWaitForPort(ctx context.Context, res chan error, endpoints map[string]int32) {
	errGroup, groupCtx := errgroup.WithContext(ctx)

	for ip, port := range endpoints {
		errGroup.Go(func() error {
			return doWaitForPortOnIp(groupCtx, ip, uint16(port))
		})
	}

	res <- errGroup.Wait()
}

const (
	_BACKOFF      = 500 * time.Millisecond
	_DIAL_TIMEOUT = 1 * time.Second
)

func doWaitForPortOnIp(ctx context.Context, ip string, port uint16) error {
	address := fmt.Sprintf("%s:%d", ip, port)
	dialer := net.Dialer{
		Timeout: _DIAL_TIMEOUT,
	}

	for {
		conn, err := dialer.DialContext(ctx, "tcp", address)
		if err == nil {
			conn.Close()
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(_BACKOFF):
			// keep going
		}
	}
}
