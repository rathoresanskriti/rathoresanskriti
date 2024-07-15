
package routes

import (
	"main/controllers"
	"github.com/gin-gonic/gin"
)

func UserRouter(r *gin.Engine) {
	r.POST("/login", controllers.Login)
	r.POST("/user", controllers.AddUser)
	//r.GET("/page", controllers.GetUsersWithPagination )
   // r.GET("/search",controllers.SearchUsers)
	protected := r.Group("/").Use(controllers.JWTAuthMiddleware())
	{
		protected.GET("/user/:id", controllers.GetUser)
		protected.PUT("/user/:id", controllers.UpdateUser)
		protected.GET("/user", controllers.GetAllUsers)
		protected.DELETE("/user/:id", controllers.DeleteUser)
        
	}
}
