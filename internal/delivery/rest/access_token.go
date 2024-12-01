package rest

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

type AccessToken struct {
}

func (svc *AccessToken) BusinessToBusiness(c echo.Context) error {
	return c.NoContent(http.StatusOK)
}
