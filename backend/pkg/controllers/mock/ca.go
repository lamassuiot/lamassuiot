package mock

import (
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/controllers"
	coreMock "github.com/lamassuiot/lamassuiot/core/v3/pkg/services/mock"
)

type MockCAHttpRoutes struct {
	svc coreMock.MockCAService
}

func NewMockCAHttpRoutes() controllers.CAHttpRoutes {
	return &MockCAHttpRoutes{
		svc: coreMock.MockCAService{},
	}
}

func (m *MockCAHttpRoutes) GetCryptoEngineProvider(ctx *gin.Context) {
	ctx.JSON(200, gin.H{})
}

func (m *MockCAHttpRoutes) CreateCA(ctx *gin.Context) {
	ctx.JSON(200, gin.H{})
}

func (m *MockCAHttpRoutes) GetStats(ctx *gin.Context) {
	ctx.JSON(200, gin.H{})
}

func (m *MockCAHttpRoutes) GetStatsByCAID(ctx *gin.Context) {
	ctx.JSON(200, gin.H{})
}

func (m *MockCAHttpRoutes) GetCARequestByID(ctx *gin.Context) {
	ctx.JSON(200, gin.H{})
}

func (m *MockCAHttpRoutes) DeleteCARequestByID(ctx *gin.Context) {
	ctx.JSON(200, gin.H{})
}

func (m *MockCAHttpRoutes) RequestCA(ctx *gin.Context) {
	ctx.JSON(200, gin.H{})
}

func (m *MockCAHttpRoutes) ImportCA(ctx *gin.Context) {
	ctx.JSON(200, gin.H{})
}

func (m *MockCAHttpRoutes) UpdateCAMetadata(ctx *gin.Context) {
	ctx.JSON(200, gin.H{})
}

func (m *MockCAHttpRoutes) UpdateCAIssuanceExpiration(ctx *gin.Context) {
	ctx.JSON(200, gin.H{})
}

func (m *MockCAHttpRoutes) GetCAsByCommonName(ctx *gin.Context) {
	ctx.JSON(200, gin.H{})
}

func (m *MockCAHttpRoutes) GetAllCAs(ctx *gin.Context) {
	ctx.JSON(200, gin.H{})
}

func (m *MockCAHttpRoutes) GetAllRequests(ctx *gin.Context) {
	ctx.JSON(200, gin.H{})
}

func (m *MockCAHttpRoutes) GetCARequests(ctx *gin.Context) {
	ctx.JSON(200, gin.H{})
}

func (m *MockCAHttpRoutes) GetCAByID(ctx *gin.Context) {
	ctx.JSON(200, gin.H{})
}

func (m *MockCAHttpRoutes) DeleteCA(ctx *gin.Context) {
	ctx.JSON(200, gin.H{})
}

func (m *MockCAHttpRoutes) UpdateCAStatus(ctx *gin.Context) {
	ctx.JSON(200, gin.H{})
}

func (m *MockCAHttpRoutes) GetCertificateBySerialNumber(ctx *gin.Context) {
	ctx.JSON(200, gin.H{})
}

func (m *MockCAHttpRoutes) GetCertificates(ctx *gin.Context) {
	ctx.JSON(200, gin.H{})
}

func (m *MockCAHttpRoutes) GetCertificatesByCA(ctx *gin.Context) {
	ctx.JSON(200, gin.H{})
}

func (m *MockCAHttpRoutes) GetCertificatesByCAAndStatus(ctx *gin.Context) {
	ctx.JSON(200, gin.H{})
}

func (m *MockCAHttpRoutes) GetCertificatesByStatus(ctx *gin.Context) {
	ctx.JSON(200, gin.H{})
}

func (m *MockCAHttpRoutes) GetCertificatesByExpirationDate(ctx *gin.Context) {
	ctx.JSON(200, gin.H{})
}

func (m *MockCAHttpRoutes) UpdateCertificateStatus(ctx *gin.Context) {
	ctx.JSON(200, gin.H{})
}

func (m *MockCAHttpRoutes) UpdateCertificateMetadata(ctx *gin.Context) {
	ctx.JSON(200, gin.H{})
}

func (m *MockCAHttpRoutes) ImportCertificate(ctx *gin.Context) {
	ctx.JSON(200, gin.H{})
}

func (m *MockCAHttpRoutes) SignCertificate(ctx *gin.Context) {
	ctx.JSON(200, gin.H{})
}

func (m *MockCAHttpRoutes) SignatureSign(ctx *gin.Context) {
	ctx.JSON(200, gin.H{})
}

func (m *MockCAHttpRoutes) SignatureVerify(ctx *gin.Context) {
	ctx.JSON(200, gin.H{})
}
