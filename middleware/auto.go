package middleware

import (
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// 返回一个 Gin 中间件函数，在每个请求到达路由前执行。
func AuthMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// 1. 检查请求头
		authHeader := ctx.GetHeader("Authorization")
		if authHeader == "" {
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"error": "require authorization",
			})
			// 该方法可以立即停止当前请求的后续执行链，防止后续的中间件和处理程序被执行。
			ctx.Abort()
			return
		}
		// 2. 验证token：验证格式是否为Bearer <token>，并提取 token 字符串
		parts := strings.SplitN(authHeader, " ", 2)
		if !(len(parts) == 2 && parts[0] == "Bearer") {
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authorization header format must be Bearer {token}",
			})
			ctx.Abort()
			return
		}

		tokenString := parts[1]
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims,
			func(token *jwt.Token) (interface{}, error) {
				return []byte("f47ac10b7dc959e9487c96a3d61ca9aa6390b6c7a61b78b271cf9c99562319"), nil
			})
		if err != nil || !token.Valid {
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid or expired Token",
			})
			ctx.Abort()
			return
		}

		ctx.Set("userID", claims.UserID)
		// 调用链路中下一个handlers
		ctx.Next()
	}
}

// 自定义JWT声明
type Claims struct {
	UserID uint `json:"user_id"`
	jwt.RegisteredClaims
}
