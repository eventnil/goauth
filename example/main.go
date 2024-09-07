package main

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"

	"github.com/c0dev0yager/goauth"
)

var redisClient *redis.Client

const (
	authID = "1"
	role   = "testing"
)

func main() {
	options := redis.Options{Addr: "127.0.0.1:6379"}
	redisClient = redis.NewClient(&options)

	cfg := goauth.Config{
		JwtKey:            "testkey",
		JwtValidityInMins: 1,
		EncKey:            "22222222rSfbC5oXa5ugZ21111111111",
		EnvIV:             "16-Bytes--String",
	}
	goauth.NewSingletonClient(cfg, redisClient)
	cl := goauth.GetClient()

	t1 := goauth.TokenValue{AuthID: authID, Role: role}
	// t2 := goauth.TokenDTO{AuthID: "2", Role: role}
	ctx := context.Background()
	token, err := cl.CreateToken(ctx, t1)
	if err != nil {
		fmt.Println(err)
		return
	}
	// fmt.Println(goauth.MapToString(token))
	time.Sleep(time.Minute * 2)
	_, err = cl.Validate(ctx, token.AccessToken)
	if err != nil {
		fmt.Println(err)
	}

	// newToken, err := cl.RefreshToken(ctx, token.RefreshKey, token.AccessToken)
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }

	// fmt.Println(newToken.RefreshKey)
}
