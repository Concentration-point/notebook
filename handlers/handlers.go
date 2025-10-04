package handlers

import (
	"net/http"
	"strings"
	"time"

	"github.com/Concentration-point/notebook/config"
	"github.com/Concentration-point/notebook/middleware"
	"github.com/Concentration-point/notebook/models"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jinzhu/gorm"
	"golang.org/x/crypto/bcrypt"
)

// 注册参数请求体
type RegisterRequest struct {
	Username string `json:"username" binding:"required,min=3,max=20"`
	Password string `json:"password" bingding:"required,min=6"`
}

func Register(c *gin.Context) {
	// 1. 绑定并校验请求参数
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    400,
			"message": "参数错误：" + err.Error(),
		})
		return
	}

	// 2. 校验用户名是否存在
	var existingUser models.User
	err := config.DB.Where("username = ?", req.Username).First(&existingUser).Error
	if err != nil {
		// 关键修改：判断错误内容是否包含 "record not found"
		if strings.Contains(err.Error(), "record not found") {
			// 没找到用户，继续注册流程
		} else {
			// 数据库错误
			c.JSON(http.StatusInternalServerError, gin.H{
				"code":    500,
				"message": "数据库查询失败：" + err.Error(),
			})
			return
		}
	} else {
		// 用户已存在，返回 409
		c.JSON(http.StatusConflict, gin.H{
			"code":    409,
			"message": "用户名已被占用",
		})
		return
	}

	// 3. 密码加密
	hashedPassword, err := bcrypt.GenerateFromPassword(
		[]byte(req.Password),
		bcrypt.DefaultCost, // 默认加密强度为10，越高越安全但耗时
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    500,
			"message": "密码加密失败" + err.Error(),
		})
		return
	}

	// 4. 将用户存到数据库中
	newUser := models.User{
		Username: req.Username,
		Password: string(hashedPassword), // 加密后的密码
	}
	if err := config.DB.Create(&newUser).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    500,
			"message": "用户创建失败" + err.Error(),
		})
		return
	}

	// 5. 返回注册成功的响应
	c.JSON(http.StatusCreated, gin.H{
		"code":    201,
		"message": "用户创建成功",
		"data": gin.H{
			"user_id":  newUser.ID,
			"username": newUser.Username,
		},
	})

}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// 登录接口，用于生成JWT
func Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    400,
			"message": "参数错误：" + err.Error(),
		})
		return
	}

	// 2. 查询用户是否存在
	var user models.User
	if err := config.DB.Where("username = ?", req.Username).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusUnauthorized, gin.H{
				"code":    401,
				"message": "用户名或密码错误",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    500,
			"message": "数据库查询失败：" + err.Error(),
		})
		return
	}

	// 3.校验密码
	if err := bcrypt.CompareHashAndPassword(
		[]byte(user.Password),
		[]byte(req.Password),
	); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"code":    401,
			"message": "用户名或密码错误",
		})
		return
	}

	// 4. 生成JWT
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &middleware.Claims{
		UserID: user.ID, // 存储用户ID（后续接口通过 Token 获取）
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime), // 过期时间
			IssuedAt:  jwt.NewNumericDate(time.Now()),     // 签发时间
			Issuer:    "notepad-app",                      // 签发者（自定义）
		},
	}

	// 生成token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte("f47ac10b7dc959e9487c96a3d61ca9aa6390b6c7a61b78b271cf9c99562319"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    500,
			"message": "Token 生成失败：" + err.Error(),
		})
		return
	}

	// 5. 登录成功
	c.JSON(http.StatusOK, gin.H{
		"code":    200,
		"message": "登录成功",
		"data": gin.H{
			"token":      tokenString,
			"expires_at": expirationTime.Unix(), // Token 过期时间（时间戳）
			"user": gin.H{
				"id":       user.ID,
				"username": user.Username,
			},
		},
	})
}

// NoteRequest 笔记请求参数结构体（创建/更新通用）
type NoteRequest struct {
	Title   string `json:"title" binding:"required,max=100"` // 标题最多100字
	Content string `json:"content"`
}

func CreateNote(c *gin.Context) {
	// 获取在拦截器中设置用户id
	// 1. 从 Token 中获取当前用户 ID
	userID, exist := c.Get(("userID"))
	if !exist {
		c.JSON(http.StatusUnauthorized, gin.H{
			"code":    401,
			"message": "未获取到用户信息",
		})
		return
	}

	// 2. 绑定并校验请求参数
	var req NoteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    400,
			"message": "参数错误：" + err.Error(),
		})
		return
	}

	// 3. 保存笔记到数据库
	newNote := models.Note{
		Title:   req.Title,
		Content: req.Content,
		UserID:  userID.(uint), // 从上下文获取的 userID 是 interface{}，需断言为 uint
	}
	if err := config.DB.Create(&newNote).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    500,
			"message": "笔记创建失败：" + err.Error(),
		})
		return
	}

	// 4. 返回创建成功响应
	c.JSON(http.StatusCreated, gin.H{
		"code":    201,
		"message": "笔记创建成功",
		"data":    newNote,
	})
}

func GetNote(c *gin.Context) {
	// 1. 获取当前用户的id 和 路径中笔记的id
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"code":    401,
			"message": "未获取到用户信息",
		})
		return
	}

	noteID := c.Param("id")

	// 2. 查询笔记
	var note models.Note
	if err := config.DB.
		Where("id = ? AND user_id = ?", noteID, userID.(uint)).
		First(&note).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{
				"code":    404,
				"message": "笔记不存在或无权限查看",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    500,
			"message": "笔记查询失败：" + err.Error(),
		})
		return
	}

	// 3. 返回单条笔记详情
	c.JSON(http.StatusOK, gin.H{
		"code":    200,
		"message": "查询成功",
		"data":    note,
	})
}

// GetNotes 获取当前用户的所有笔记
func GetNotes(c *gin.Context) {
	// 1. 获取当前用户 ID
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"code":    401,
			"message": "未获取到用户信息",
		})
		return
	}

	// 2. 查询当前用户的所有笔记（按创建时间倒序）
	var notes []models.Note
	if err := config.DB.
		Where("user_id = ?", userID.(uint)).
		Order("created_at DESC").
		Find(&notes).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    500,
			"message": "笔记查询失败：" + err.Error(),
		})
		return
	}

	// 3. 返回笔记列表
	c.JSON(http.StatusOK, gin.H{
		"code":    200,
		"message": "查询成功",
		"data":    notes,
		"count":   len(notes), // 笔记总数
	})
}

// UpdateNote 更新笔记（仅允许更新自己的笔记）
func UpdateNote(c *gin.Context) {
	// 1. 获取当前用户 ID 和笔记 ID
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"code":    401,
			"message": "未获取到用户信息",
		})
		return
	}

	noteID := c.Param("id")

	// 2. 绑定并校验更新参数
	var req NoteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    400,
			"message": "参数错误：" + err.Error(),
		})
		return
	}

	// 3. 先查询笔记是否存在且归属当前用户
	var note models.Note
	if err := config.DB.
		Where("id = ? AND user_id = ?", noteID, userID.(uint)).
		First(&note).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{
				"code":    404,
				"message": "笔记不存在或无权限更新",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    500,
			"message": "笔记查询失败：" + err.Error(),
		})
		return
	}

	// 4. 更新笔记内容
	note.Title = req.Title
	note.Content = req.Content
	if err := config.DB.Save(&note).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    500,
			"message": "笔记更新失败：" + err.Error(),
		})
		return
	}

	// 5. 返回更新成功响应
	c.JSON(http.StatusOK, gin.H{
		"code":    200,
		"message": "笔记更新成功",
		"data":    note,
	})
}

// DeleteNote 删除笔记（仅允许删除自己的笔记）
func DeleteNote(c *gin.Context) {
	// 1. 获取当前用户 ID 和笔记 ID
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"code":    401,
			"message": "未获取到用户信息",
		})
		return
	}

	noteID := c.Param("id")

	// 2. 校验笔记归属权并删除（gorm 的 Delete 支持带条件删除）
	result := config.DB.
		Where("id = ? AND user_id = ?", noteID, userID.(uint)).
		Delete(&models.Note{})

	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    500,
			"message": "笔记删除失败：" + result.Error.Error(),
		})
		return
	}

	// 3. 检查是否删除了数据（RowsAffected 为 0 表示未找到）
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{
			"code":    404,
			"message": "笔记不存在或无权限删除",
		})
		return
	}

	// 4. 返回删除成功响应
	c.JSON(http.StatusOK, gin.H{
		"code":    200,
		"message": "笔记删除成功",
	})
}
