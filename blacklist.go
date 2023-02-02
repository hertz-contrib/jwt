// The MIT License (MIT)
//
// Copyright (c) 2016 Bo-Yi Wu
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
// This file may have been modified by CloudWeGo authors. All CloudWeGo
// Modifications are Copyright 2022 CloudWeGo Authors.

package jwt

import (
	"context"
	"time"

	"github.com/go-redis/redis/v8"
)

type (
	BlackListStoreModel interface {
		Set(ctx context.Context, key, value string) error
		Get(ctx context.Context, key string) (string, error)
		Remove(ctx context.Context, key string) error
	}

	BlackListRedisStore struct {
		rdb        *redis.Client
		expiration time.Duration
	}
)

func NewBlackListRedisStore(rdb *redis.Client, expiration time.Duration) *BlackListRedisStore {
	return &BlackListRedisStore{
		rdb:        rdb,
		expiration: expiration,
	}
}

func (m *BlackListRedisStore) Set(ctx context.Context, key, value string) error {
	return m.rdb.Set(ctx, key, value, m.expiration).Err()
}

func (m *BlackListRedisStore) Get(ctx context.Context, key string) (string, error) {
	return m.rdb.Get(ctx, key).Result()
}

func (m *BlackListRedisStore) Remove(ctx context.Context, key string) error {
	return m.rdb.Del(ctx, key).Err()
}
