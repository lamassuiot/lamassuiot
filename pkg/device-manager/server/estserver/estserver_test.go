package estserver

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"strconv"
	"testing"

	"github.com/go-kit/kit/log"

	"github.com/lamassuiot/lamassuiot/pkg/device-manager/common/dto"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/server/mocks"
	verify "github.com/lamassuiot/lamassuiot/pkg/device-manager/server/utils"
	"github.com/lamassuiot/lamassuiot/pkg/utils"
)

func TestReenroll(t *testing.T) {

	srv, ctx := setup(t)
	csr1Str := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ3BUQ0NBWTBDQVFBd1lERUxNQWtHQTFVRUJoTUNSVk14RVRBUEJnTlZCQWdNQ0VkcGNIVjZhMjloTVJFdwpEd1lEVlFRSERBaEJjbkpoYzJGMFpURU1NQW9HQTFVRUNnd0RTVXRNTVF3d0NnWURWUVFMREFOYVVFUXhEekFOCkJnTlZCQU1NQmtSRlZrbERSVENDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFLQlEKWU1PS2tKaEZIVzdmc2xGcVJYRjFYaFE2eEM1YW9FSzhCcVV1bkkxTThwbTA1aW02cXlLcndOajBjREVCMDI5SQoxNWI1SG5scFV5VytwQnprWHluM2xKZ29qV0FPeWdQZVdDWk1Yb2pTOFZjRzdNRzVyQmlwWU8vK25WbllsUnlDCkVMZEg3QnNtOFM1ZlRjUHZYSThnenRmc1Z0cnhmZERwSjl2Mi8rUFNzOGFwS1d1aTd4am9LU3dBTmhvci9WQ1UKZ2Nia1A3T0lnL01GcHVQRHRQQ0NaclR0SWVrM3lvWDV6dXJpZ0k3VEFnelBuNXVaRzhnL2lGbmU5V0ZPaGJwUQpNaXk0M2s1VnlXMDhIb3hKUkhaMW9YWDAydjBYVU5LY1A4ZEphVnE5cXJKTVZPSWV6eEpGVm11TmhhTC9ibVFHClNBUUZFK2VxUW1aYlVkVmhrT3NDQXdFQUFhQUFNQTBHQ1NxR1NJYjNEUUVCQ3dVQUE0SUJBUUJhbjBUMnExcVAKbzY2S3o4U2VmOVNNU004cEN1MFJVbWRCWVVtbytTbWtCYjgxUnFxTzFnK29IRVpUalQrejlQWTI3OEVWTEU4VwpWeTBiWVFDc2tyb0JpWWgwNmtScmgrSDFQc1drOXUrOUh4QXVPcjZKMm1iL3ZmdER5S3kvMW1YdGRDT3ZZZ3lyCmt4SWQzT0dNeFhVM3BCbXFzNURpL2lFY1F4REJhYVErRlE2a3NNZm9DMmJTcWFLVngrR2lxMC9YNUxrd0hTVUwKMVJNVWpWS0VBTmZWODNhVDREVXNINTI5ZWtkblltckF6OGlabUdldlhka2tTNzQ5WWttTFVrTlVRQXE0cmk1ZgpUTnNqcy9UTTN1WGpNbkpNclBEdTcrK2VqM1RqZWxCUlhlcUs1Zm1rcW5UN1Exa0xMYTB1bWJBZ1RzSUwrdHJJClVkU25qWGp2cnpMTQotLS0tLUVORCBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0K"
	csr1, _ := StringToCSR(csr1Str)
	ctx = context.WithValue(ctx, "DBInsertDeviceCertHistory", false)
	ctx = context.WithValue(ctx, "SignCertificateRequestFail", false)

	cert1Str := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZRekNDQXlzQ0ZGcXBPNGNjMWlHTElqMVUxTzExZElzOVVWa3RNQTBHQ1NxR1NJYjNEUUVCQ3dVQU1Gd3gKQ3pBSkJnTlZCQVlUQWtWVE1SRXdEd1lEVlFRSURBaEhhWEIxZW10dllURVJNQThHQTFVRUJ3d0lRWEp5WVhOaApkR1V4RERBS0JnTlZCQW9NQTBsTFRERU1NQW9HQTFVRUN3d0RXbEJFTVFzd0NRWURWUVFEREFKRFFUQWVGdzB5Ck1qQXlNVFl4TVRVd016ZGFGdzB5TXpBeU1URXhNVFV3TXpkYU1HQXhDekFKQmdOVkJBWVRBa1ZUTVJFd0R3WUQKVlFRSURBaEhhWEIxZW10dllURVJNQThHQTFVRUJ3d0lRWEp5WVhOaGRHVXhEREFLQmdOVkJBb01BMGxMVERFTQpNQW9HQTFVRUN3d0RXbEJFTVE4d0RRWURWUVFEREFaRVJWWkpRMFV3Z2dJaU1BMEdDU3FHU0liM0RRRUJBUVVBCkE0SUNEd0F3Z2dJS0FvSUNBUUMzbHJ5d2tnT3UxSC82Qm5EYzdOYlRFYVdTSVZrZHJhUlZ0S0l1MnV6NW5wMU8Kd2ZCdnRTUjJOMWh6WXlaRGxlQ21NNGJnOS8zckx6dEw3b1V4cWZqZDFUUmlUV1hoZUpTQm14ZFpsaEdld2p3dwpieWNtb0d3a3hBbmxCV2k3STBjN2ZObjZ3Wi9vMjNINTcrenFtcGhvbGZXeW9qVTFvUkliU21vNUR5S2ZBN1ArCjBWR3ZWUkM1ZkMxcVV6TUE4UnVESlFUY0RlWU4zZGc2amp6MnBrQ1JiV0NDd29KZmxIUlc2UW5MUXlTc2VzdEgKT3ZabWUxWGYzZjNtUGVUVzBZeWEyWFdBRE53NjBRdWVTc2xFMGJsckpmSTcxMHFXaWpwNnpNSnZGMW5TQzFnSwp4SndPd3pmeFlzTy9RVitKckQyenBJWGcwSkdFd3pZOGw4WnFac0Zva3dsREFDKzllbkkrZ2VSUUl2Nm9COUVzCnVnNWMxZmRMZlI1dFd2cTFwVnY2SzdzSW9VUTZwNzF6aWRYVUJqaGVDbkdqeHl1eU5YcTN3S0ZuVHp4QWI3Q24KeHJ3ODRSUHRDSU16WU9jLzRKNHBsQkpqR0VkaDk3dmRKWDVjNDJWV2xRbFMvdlpGWENtcE5IR1VFQlZnbW43VApCZEhObitoSTJaOXM5eE9ZYkQrREpoNjVLVEdSVWdoT1R2N2liMlQyeXpuL2E0blNVWVp1MXBpb1R0cXdPdkRIClNtaG9hb1hWL2d6MkNxRjd0VkNSU0RPMXVtV2E4R2JBNGFtb1pYY2RONXprMjRIRjJJdGd4TlV6RTc4eE5MdWkKMEpTSGpOS3JCbnpxUUFscE9DRitjR0ozU1dtdW1ua0JYMkFpSllZQU55bEoycFFoZ1RFRmp5VGcxeGUvYlFJRApBUUFCTUEwR0NTcUdTSWIzRFFFQkN3VUFBNElDQVFDUzYvZ2d2dHE3bElLd3pmN0I5L01QOG5zN2ZBSzRIK2dGCmlha3hDYytpQVFsUEVFeVEwejNocEFlcGJ6c2x1a2U4WTc2enUzLytDdW9tU1hmN3NCMVh5RjNzR2dTS3IrS0YKdmE0Z20rY3Q5eStpUDRWZk96eUVsdWxQblF4enhvSyt2aVBHTlZzeENXdTRqWG5YeVBmSkR1RnV0akJBeVR4aApSZ2ZEcFVJdWtoWllPSE4vNS90T3htRjF5aEs2OTNPQUJNcHAwbU9YaTJ4Y3B4RW9UWWR5d0l0MXRvbkoyWXFnCnpuYy8wUGpNbGZ1YkVrQmtNVFNoWjM1R2R2ZlUvNTRJNXlHc0IzN2lPTWkrb1dzL0p4S0NqUDg2RFVOaS9mT2YKMFRMWUJHWnd4UGxGK09pR3dhcXVBaTE1eFpkUUQ0SFBIekt4RjdNZUFKN3JtSkhET3lSU3ZzQkt0QXlVNzc2YQp3TElnYXZ5ZlMrNCswSDZ1WGpmQVpIMWExSXFVWVZEcklWejZjWXlFQTVsV0ZEdU4wSDByN2NJaGk3UUE1WjZyCkJFcWlCZUFQRWJoZU5XSk9idjB0ZmR4RVp5dFduT0REY0hVVnRxT2pUU01CSG9HYmhtcHZNbk5zUVk3ZXl6YUYKZGdzQUx5UmZLMzB5Q1dKNjZZS3MrM2NTUDZLRFB0MVpWaVBXZ0k1aTkxQnRBYXNLLzdZdVZkTmUyYUhuUER0bgp4Qzh5ZHF0czJpc3JyZDNUOGx1ODk3SUFScVBKQVZCb253RUozeE9rZlZ6bFRFSXdWeHljVW5vWEtrL3lPNVRkCk5QRkhCRXZ5cFYrUW91MnducG1qMnh5R2FHV3UwQUw0aXR3SGloRERXRGl5VS9rVHpoeUVUOWtPL3pqZ3QwM2MKRU9KM3hrWkx2QT09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0="
	cert1, _ := StringToCert(cert1Str)

	cert1ErrorStr := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZtekNDQTRPZ0F3SUJBZ0lVRGp5b0NYVGFvc3lpNTYwcDdRUUlwZEZtM0JVd0RRWUpLb1pJaHZjTkFRRUwKQlFBd1hURUxNQWtHQTFVRUJoTUNSVk14RVRBUEJnTlZCQWdNQ0VkcGNIVjZhMjloTVJFd0R3WURWUVFIREFoQgpjbkpoYzJGMFpURU1NQW9HQTFVRUNnd0RTVXRNTVF3d0NnWURWUVFMREFOYVVFUXhEREFLQmdOVkJBTU1BME5CCk16QWVGdzB5TWpBeU1UZ3hNREV4TXpCYUZ3MHlNekF5TVRneE1ERXhNekJhTUYweEN6QUpCZ05WQkFZVEFrVlQKTVJFd0R3WURWUVFJREFoSGFYQjFlbXR2WVRFUk1BOEdBMVVFQnd3SVFYSnlZWE5oZEdVeEREQUtCZ05WQkFvTQpBMGxMVERFTU1Bb0dBMVVFQ3d3RFdsQkVNUXd3Q2dZRFZRUUREQU5EUVRNd2dnSWlNQTBHQ1NxR1NJYjNEUUVCCkFRVUFBNElDRHdBd2dnSUtBb0lDQVFEUCtWVmM1RUgxY2lLc0FnS2NTTnVicjgwTGpXR093dENlV05LN1FWQnoKaElLWjZCWDl0MUhnTUFOOGlWdzdBcXBQUkdqcC9XNHlTNXhOMjZ5NHVoaDdSWktqN3hZSlNpTnZUZkxyT2MySwpnODByWWsxNWJZSHo4N2k2dWJ1UUtCUkFUeXM0QlA5UlRyY28wakVUQU9Hc0NpZGJtSkJ6K2RkbkxRb2NpbDBTCkxQYWtvWjVzT0Fjcmw5WWdIR3VwQThHUFBJYm5pWklhVVl1OVRUU2Vpby9Nck0zZE1Nc3prZk82THVNSVhXaDUKY25kNFZNZkx3QVFDbjJIMzY2TE9haFJwR2lhS2Z0YUErMEVzVDh1WnZUUmRlTi9OakFhVnRUQ05CNjFMR1cvago1R2M1eHhlMjNEQ0hSbHVPdzF6dFdVSlhuRVF1Wk5adDJ3UGJydWw2Q2gxdGEyQkdXK3NjTXdIK3dsSEhVMFNxCmQ3d3BTWU5xajFRWm9ZQ2pLaktnd3BwUldFWmhsQ3BUbTJWdmMrUHEwNUZVa21sV1BHMU1vN0pRVS9ZWmVzYW4KNmd1QmNJaTU0RENpZytwQWVsM2c1dEFaajFpc01iY2phU1ZVbzYwZGFtTDg2SFlDWTU5ZmZXSXFqRzBRcDNRRQo2TmVUSDVDUzhneHVGTUFiSkpUL3c1b3dQbzJIUlJWR0tteVliM1pZZUlPVzZtREQ5RzdCUWxVcWs4TlUxOS8zCmg0N0g1VHBFOS9xN251YkJmei9ONXBkMy8vOWJKem8rYUcwdHRvZmNoMDF3cDArRE1pQUpEZDVhUmdjaTQyTGMKWWdPL1lvTjVyZXFSb1J5cmtHeElPMnNVekRYMFFSTm1HbzdtNHRLajlOVWxFVkV5cXNXbmpFQWN0Wlp0Q1VJbApId0lEQVFBQm8xTXdVVEFkQmdOVkhRNEVGZ1FVNDM0VUxCRmEzWDBVQ1VYMFJLTFhFUms2NFY4d0h3WURWUjBqCkJCZ3dGb0FVNDM0VUxCRmEzWDBVQ1VYMFJLTFhFUms2NFY4d0R3WURWUjBUQVFIL0JBVXdBd0VCL3pBTkJna3EKaGtpRzl3MEJBUXNGQUFPQ0FnRUFNby8xb3dFUVhOUTAzbVp4ZzFmSzk0VDNpQnhFYjJxa3JhOTBCVTBUOXZKSQpVSVhHTFZhaGg0ZGoxY09nb1pkWmFWQm80TDNtaUoxaFliUTJNVGk1V0w4R21IYmpveDJ6OVhMR3p1bjBRNHNFClgzRjcxbCtpcFFobXVsdHpWbC9VMEYrSWJPcWVyQmVpamRaaW0vYzdDSnR5MmVyNWpOb0xmV0FpNVRKVEphcmMKeHorbC9rS1dvVlJGUkRxVGNGVk4xUmZ1RVlLQjBjREp2SkJvL1pnN1ZmaTdXb1B1NlI5ZWM2VEcvd204Vm1MdApwQXc2QjQ5R0xJbDBqNzdjOHdxcmhjVjg2OFVvMGpWRjZFcGRVWG5nTTZGcjRkSzhFQVl5cEhDQnlkZTlRRC9HClpIWXJYQjhScTM4WjlpVjFOZnRqbTB1Sk1rZFNKZFFyT2pPTHJSdHR0S3FoTE1hVEtSb3FqZ0hXOEV6MXFnalgKL29vT01LbEsvUk40dVFEd254WkpjYVlZQ3JWTHp3UGlwNDVsK2JlY3YvQmEyQytqTktCTWZJY2lySUI3a0FQMAo2RkxDdUFxTVBxQ29HK0hsYytjL0FlRmRXcXNYZVI5ckNRbUIzUUU0MndiQTJ2TlJXc0NoRVcvc0RUYkJ4T3FJCkVDYUZUN1RvQ2FhSExwdDExTGpReVhMK0FNUVNZV2NLdmZSaWY3RU5PcVBXcEFKbThIOTdRcjJYdEpMdzdrcG0KNzd0S0E5VXBzT1p5VDF0b1IyYWwwak5RTTJYOFkwVzNGcUNzaE40OHUydjNkL01WYWhIejlDK2NuZW12R0VkVQpUUy9tckdMT0RCenVsS0dCRUlzamtkeUVIelA3SFVSUVNpai9PU0xBcHRZR3lGbytpcmZzRnFjMEVRd1hvTWc9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0="
	certError, _ := StringToCert(cert1ErrorStr)

	csr2Str := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ25EQ0NBWVFDQVFBd1Z6RUxNQWtHQTFVRUJoTUNSVk14Q2pBSUJnTlZCQWdNQVVFeENqQUlCZ05WQkFjTQpBVUV4Q2pBSUJnTlZCQW9NQVVFeENqQUlCZ05WQkFzTUFVRXhHREFXQmdOVkJBTU1EMlZ5Y205eVJHVjJhV05sClFubEpaRENDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFOVzV3Rm5YT25vb29SbGUKb09mcHNwZmVWRmJhZ3R5NzNaNnhSQ0R6ZXMxYVByUURPTjZ6OHhydGdjZDRKa0REMDFnbWNYLzArakUvdnkybwpKT015cGlJbGluVVQyMFhoM0ZxazV1OG5IeXIxSTI1L04rTGdQdmx6eHIyVjlaOGQ3Y0VkcjhzVXBqa3ptRDhICmo0QjVLN1pXTHd6NktGRW5aY3J2SWtzZHVJeEkxMDMvS2JGdjRWTi9WTndPeEpaVFFkMFRYdVU2RE0rRDcwWU4KZUxWcVovc0krdXluM3o5bXlhZ1FIS1ZkblgwSDltQ3ZOdVBQelNUTkxvaG1GNkRLSHhhV1d4NHQ3TzNMTnU3dQpCMmF2b2JmdnNBS1ljWER3SjgyTXNIMGkvRDZtaVBvUE1sL1lvZFM4d3VkZ2xMWUhobWc0VmlvdzJmQ0E0RmVkCnJ5Z1o3N0VDQXdFQUFhQUFNQTBHQ1NxR1NJYjNEUUVCQ3dVQUE0SUJBUUFzMFJqTS9qclJGem5FU3ljRXlsSjgKWlNZTjE1ODNJNzFUeXFXQWE2RkEwK1htYVlDSTgyWHVSL0owNjY1N2ZjTEhicG1hTExCYnJzRDN4MkJUa29VSgpQQzdDV25kVmUvOXllYkZRaFdkOWdwcVA2UHBOZW1TN3ZmZ0pOaXVXb3hXS2tJOWNzZEh5emNWV0hsRGhzZllJClp5NHM4dGwxNkJkTDVHRnlBbkdOdFhubEZlYkdYOVZCays1YlU2WkhlaVd5ejJ5OXcwM1Y1RnFZeEhRV1VaQzkKcTBHRWFHYTBUaGtWbVU4S2VTYUs4MXBjYWZTeW5HeVpPbkI4VzFmbEwzVEJBNGxJQ3VBTVJkcUo5UEsyTlZIegp6aUVOWUJYMDRVWGNPUzJDVHcwekVTanpIR1JUaUplYy9aS2swcVM0TGljNlRxN2RFb3Vtclh2Kzd3MHZJZ3RVCi0tLS0tRU5EIENFUlRJRklDQVRFIFJFUVVFU1QtLS0tLQoK"
	csr2, _ := StringToCSR(csr2Str)

	//provisioned
	csr7Str := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ21EQ0NBWUFDQVFBd1V6RUxNQWtHQTFVRUJoTUNSVk14Q2pBSUJnTlZCQWdNQVVFeENqQUlCZ05WQkFjTQpBVUV4Q2pBSUJnTlZCQW9NQVVFeENqQUlCZ05WQkFzTUFVRXhGREFTQmdOVkJBTU1DM0J5YjNacGMybHZibVZrCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBc29yTG5tNmk5czlHMTVmVkROS1UKdFhzanJmWGZRb3hWazBYTDA2bFkrZkIvSzgwa3ZTbjhQWGRGQzdreTVTK0JyUEtZdHNlS0xOTjZyYkpFUkVuVQpab3lmWkdPbkwveU90TTB6anA2V21NNmxpSGhqeDE0NENscDNKNE4xTDJHc3cwS25wMG5Ea2JxTERlMjJRTjlZCnNCNEVaVHlJcTlQUFpzNTAzbVNGL1RsZ2dIc0NocFI1NEFKa1VNNjBDbGtybFprOHdmYyt2U3pTeE45QVlxSGIKTjIwVUpnV1prOXVnekdTZWQvMDdpL2FXanFNWXcwb1RrQTJQbkNERW1JOVplUHFjaGFZTG9HZW5OaHJJSkNlcgowN1VrVHZMVGljdkhXeVZHdEIxVDV1RUo4NFZXZHhSUDJhWEJISEtQVFVGNXRJVm9qT1N1Yml5MG1uSDVGd0p5CkR3SURBUUFCb0FBd0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dFQkFIWjZNUWJSRTNWZHN6U3J2VXhEbXAwZXBnTTYKaURUcjRoMi9KbklpS1prcnROYXRrbWFiaVJjM1Vkd0p0V3JxRWNHOW5GdkpYQW9TNUdpTjhxeTRkeHRQSVVURwpMUGlwREhmdU10bU5KZTkxdHRiWFVSV0VaRkNPL2RSdFpzSFZocUNBai9OTWxtdzVTU3BKMTIrYzFKTDR4bm1RClRzVEhqTk5YMytSMmJrVE5pUVNyY3JVUXNmK1dCY21OSHR2aW42aVJZd29KbDQ2cmFhM3ZqQUFxa3o2cldkRG4KN1A4YUV4aVBoSCtnbitDbWxUWGx4cDhSZGtPdmxWSFcxN2xoQzVXNGtGaHlBUFJXNWZkaGlvREp0SEl5ZUZLaQpYMkxzL25RZEwySTNtZmtPNWVqOUdMTU5DZnVtaU02Um1PL2FwMDRObzJUOGsyeTBINXg4azJ2ei9naz0KLS0tLS1FTkQgQ0VSVElGSUNBVEUgUkVRVUVTVC0tLS0tCgoK"
	csr7, _ := StringToCSR(csr7Str)

	testCases := []struct {
		name string
		cert *x509.Certificate
		csr  *x509.CertificateRequest
		aps  string
		ret  error
	}{
		//{"Cert Date Conversion Error", cert1, csr1, "a", errors.New("parsing time \"\" as \"2006-01-02 15:04:05 -0700 MST\": cannot parse \"\" as \"2006\"")},

		{"Error Decommisioned Device", cert1, csr1, "a", errors.New("Cant reenroll a device with status: CERT_REVOKED")},
		{"Error Insert Log", cert1, csr1, "a", errors.New("Could not insert log")},
		{"Correct", cert1, csr1, "a", errors.New("Cant reenroll ")},
		{"Error Sign Certificate RequestFail", cert1, csr1, "a", errors.New("validation error: Error revoking certificate")},
		{"Error Finding Device", cert1, csr1, "a", errors.New("Error finding device")},
		{"Error Update Status By Id", cert1, csr1, "a", errors.New("Error Update Status")},
		{"Error Update Device Certificate Serial Number By ID", cert1, csr1, "a", errors.New("Error Update Device Certificate Serial Number By ID")},
		{"Peer Certificate", certError, csr1, "a", errors.New("x509: certificate signed by unknown authority")},
		{"Expiration Date Error", cert1, csr1, "a", errors.New("Cant reenroll a provisioned device before 2 days of its expiration time")},
		{"Subject Changed", cert1, csr2, "a", errors.New("different Subject fields")},
		{"Error Insert Device Cert History", cert1, csr1, "a", errors.New("Testing DB connection failed")},
		{"Error Provisioned Device", cert1, csr7, "a", errors.New("The device already has a valid certificate")},
		{"Error Get Cert", cert1, csr1, "a", errors.New("Error getting certificate")},
		{"Error Revoke Cert", cert1, csr1, "a", errors.New("Error revoking certificate")},
		{"Error Select Device Cert History By SerialNumber", cert1, csr1, "a", errors.New("Testing DB connection failed")},
	}

	for _, tc := range testCases {

		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {
			if tc.name == "Error Decommisioned Device" {
				ctx = context.WithValue(ctx, "DBDecommisioned", true)
				ctx = context.WithValue(ctx, "DBSelectDeviceById", false)
				ctx = context.WithValue(ctx, "SignCertificateRequestFail", false)
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistoryBySerialNumberFail", false)
				ctx = context.WithValue(ctx, "GetCertFail", false)
				ctx = context.WithValue(ctx, "RevokeCertShouldFail", false)
				ctx = context.WithValue(ctx, "DBErrorLog", false)
				ctx = context.WithValue(ctx, "DBUpdateStatus", false)
				ctx = context.WithValue(ctx, "DBUpdateDeviceCertificateSerialNumberByID", false)
			} else if tc.name == "Error Finding Device" {
				ctx = context.WithValue(ctx, "DBSelectDeviceById", true)
				ctx = context.WithValue(ctx, "SignCertificateRequestFail", false)
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistoryBySerialNumberFail", false)
				ctx = context.WithValue(ctx, "GetCertFail", false)
				ctx = context.WithValue(ctx, "RevokeCertShouldFail", false)
				ctx = context.WithValue(ctx, "DBErrorLog", false)
				ctx = context.WithValue(ctx, "DBUpdateStatus", false)
				ctx = context.WithValue(ctx, "DBDecommisioned", false)
				ctx = context.WithValue(ctx, "DBUpdateDeviceCertificateSerialNumberByID", false)
			} else if tc.name == "Error Update Status By Id" {
				ctx = context.WithValue(ctx, "DBInsertDeviceCertHistory", false)
				ctx = context.WithValue(ctx, "SignCertificateRequestFail", false)
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistoryBySerialNumberFail", false)
				ctx = context.WithValue(ctx, "GetCertFail", false)
				ctx = context.WithValue(ctx, "RevokeCertShouldFail", false)
				ctx = context.WithValue(ctx, "DBErrorLog", false)
				ctx = context.WithValue(ctx, "DBUpdateStatus", true)
				ctx = context.WithValue(ctx, "DBSelectDeviceById", false)
				ctx = context.WithValue(ctx, "DBDecommisioned", false)
			} else if tc.name == "Error Update Device Certificate Serial Number By ID" {
				ctx = context.WithValue(ctx, "DBInsertDeviceCertHistory", false)
				ctx = context.WithValue(ctx, "SignCertificateRequestFail", false)
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistoryBySerialNumberFail", false)
				ctx = context.WithValue(ctx, "GetCertFail", false)
				ctx = context.WithValue(ctx, "RevokeCertShouldFail", false)
				ctx = context.WithValue(ctx, "DBErrorLog", false)
				ctx = context.WithValue(ctx, "DBUpdateStatus", false)
				ctx = context.WithValue(ctx, "DBUpdateDeviceCertificateSerialNumberByID", true)
				ctx = context.WithValue(ctx, "DBSelectDeviceById", false)
				ctx = context.WithValue(ctx, "DBDecommisioned", false)
			} else if tc.name == "Error Insert Device Cert History" {
				ctx = context.WithValue(ctx, "DBInsertDeviceCertHistory", true)
				ctx = context.WithValue(ctx, "SignCertificateRequestFail", false)
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistoryBySerialNumberFail", false)
				ctx = context.WithValue(ctx, "GetCertFail", false)
				ctx = context.WithValue(ctx, "RevokeCertShouldFail", false)
				ctx = context.WithValue(ctx, "DBErrorLog", false)
				ctx = context.WithValue(ctx, "DBUpdateStatus", false)
				ctx = context.WithValue(ctx, "DBUpdateDeviceCertificateSerialNumberByID", false)
				ctx = context.WithValue(ctx, "DBDecommisioned", false)
			} else if tc.name == "Error Revoke Cert" {
				ctx = context.WithValue(ctx, "DBInsertDeviceCertHistory", false)
				ctx = context.WithValue(ctx, "SignCertificateRequestFail", false)
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistoryBySerialNumberFail", false)
				ctx = context.WithValue(ctx, "GetCertFail", false)
				ctx = context.WithValue(ctx, "RevokeCertShouldFail", true)
				ctx = context.WithValue(ctx, "DBErrorLog", false)
				ctx = context.WithValue(ctx, "DBUpdateStatus", false)
				ctx = context.WithValue(ctx, "DBUpdateDeviceCertificateSerialNumberByID", false)
				ctx = context.WithValue(ctx, "DBDecommisioned", false)
			} else if tc.name == "Error Sign Certificate RequestFail" {
				ctx = context.WithValue(ctx, "DBInsertDeviceCertHistory", false)
				ctx = context.WithValue(ctx, "SignCertificateRequestFail", true)
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistoryBySerialNumberFail", false)
				ctx = context.WithValue(ctx, "GetCertFail", false)
				ctx = context.WithValue(ctx, "RevokeCertShouldFail", false)
				ctx = context.WithValue(ctx, "DBErrorLog", false)
				ctx = context.WithValue(ctx, "DBUpdateStatus", false)
				ctx = context.WithValue(ctx, "DBUpdateDeviceCertificateSerialNumberByID", false)
				ctx = context.WithValue(ctx, "DBDecommisioned", false)
			} else if tc.name == "Error Get Cert" {
				ctx = context.WithValue(ctx, "DBInsertDeviceCertHistory", false)
				ctx = context.WithValue(ctx, "SignCertificateRequestFail", false)
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistoryBySerialNumberFail", false)
				ctx = context.WithValue(ctx, "GetCertFail", true)
				ctx = context.WithValue(ctx, "RevokeCertShouldFail", false)
				ctx = context.WithValue(ctx, "DBErrorLog", false)
				ctx = context.WithValue(ctx, "DBUpdateStatus", false)
				ctx = context.WithValue(ctx, "DBUpdateDeviceCertificateSerialNumberByID", false)
				ctx = context.WithValue(ctx, "DBDecommisioned", false)
			} else if tc.name == "Error Select Device Cert History By SerialNumber" {
				ctx = context.WithValue(ctx, "DBInsertDeviceCertHistory", false)
				ctx = context.WithValue(ctx, "SignCertificateRequestFail", false)
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistoryBySerialNumberFail", true)
				ctx = context.WithValue(ctx, "GetCertFail", false)
				ctx = context.WithValue(ctx, "RevokeCertShouldFail", false)
				ctx = context.WithValue(ctx, "DBErrorLog", false)
				ctx = context.WithValue(ctx, "DBUpdateStatus", false)
				ctx = context.WithValue(ctx, "DBUpdateDeviceCertificateSerialNumberByID", false)
				ctx = context.WithValue(ctx, "DBDecommisioned", false)
			} else if tc.name == "Cert Date Conversion Error" {
				ctx = context.WithValue(ctx, "DateFormatError", true)
				ctx = context.WithValue(ctx, "DBErrorLog", false)
				ctx = context.WithValue(ctx, "DBUpdateStatus", false)
				ctx = context.WithValue(ctx, "DBUpdateDeviceCertificateSerialNumberByID", false)
				ctx = context.WithValue(ctx, "DBDecommisioned", false)
				ctx = context.WithValue(ctx, "DBCertDateConversionError", false)
			} else if tc.name == "Error Insert Log" {
				ctx = context.WithValue(ctx, "DBSelectDeviceById", false)
				ctx = context.WithValue(ctx, "DBInsertDeviceCertHistory", false)
				ctx = context.WithValue(ctx, "SignCertificateRequestFail", false)
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistoryBySerialNumberFail", false)
				ctx = context.WithValue(ctx, "GetCertFail", false)
				ctx = context.WithValue(ctx, "RevokeCertShouldFail", false)
				ctx = context.WithValue(ctx, "DBErrorLog", false)
				ctx = context.WithValue(ctx, "DBUpdateStatus", false)
				ctx = context.WithValue(ctx, "DBUpdateDeviceCertificateSerialNumberByID", false)
				ctx = context.WithValue(ctx, "DBDecommisioned", false)
				ctx = context.WithValue(ctx, "DBInsertLog", true)
			} else {
				ctx = context.WithValue(ctx, "DBSelectDeviceById", false)
				ctx = context.WithValue(ctx, "DBInsertDeviceCertHistory", false)
				ctx = context.WithValue(ctx, "SignCertificateRequestFail", false)
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistoryBySerialNumberFail", false)
				ctx = context.WithValue(ctx, "GetCertFail", false)
				ctx = context.WithValue(ctx, "RevokeCertShouldFail", false)
				ctx = context.WithValue(ctx, "DBErrorLog", false)
				ctx = context.WithValue(ctx, "DBUpdateStatus", false)
				ctx = context.WithValue(ctx, "DBUpdateDeviceCertificateSerialNumberByID", false)
				ctx = context.WithValue(ctx, "DBInsertLog", false)
				ctx = context.WithValue(ctx, "DBDecommisioned", false)
			}
			ctx = context.WithValue(ctx, "DBShouldFail", false)
			_, err := srv.Reenroll(ctx, tc.cert, tc.csr, tc.aps)
			if err != nil {
				if tc.ret.Error() != err.Error() {
					t.Errorf("Got result is %s; want %s", err, tc.ret)
				}

			}
		})
	}
}

func TestEnroll(t *testing.T) {
	srv, ctx := setup(t)

	csr1Str := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ2pqQ0NBWFlDQVFBd1NURUxNQWtHQTFVRUJoTUNSVk14Q2pBSUJnTlZCQWdNQVVFeENqQUlCZ05WQkFjTQpBVUV4Q2pBSUJnTlZCQW9NQVVFeENqQUlCZ05WQkFzTUFVRXhDakFJQmdOVkJBTU1BVEV3Z2dFaU1BMEdDU3FHClNJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUUN4ODkxSkZFTnpzOHdQc1RVQ2tGS0pmYWxBSGd4bklBZkYKRkNmWUJGUk44bU84T1FsNXlmV1MyWk5ub3p2NnpPblBGNFpvMGkwVldocGFhSTZtdWxpOEl6Y2cwdDMxdzllQwo4U2NBTnJQNFFJeDluR3NXV3pVNWk2NnZydzZrMWhQV0k5eDh1V0VoeW1tcFlRaEVuT2tzWHQvYXZISmppZzA1ClJQSDdkWk45UXhoaTF0WXl4N0ZSUUNadE02SFV2SGpTalFFc25rRUJkSTBaVWZkMlpTWmo2NGlCbTJ0RXkvVUoKL0NuUGJkR01PbUloZHhqY2Zva0RtTjkrdTZKT2NyYWtrT204aXhrRHlvTGtEWVUrVllOelROZmNSUVR5R0IvZgpUMDJEMEdLWUZOKy9FZ09vR0tuU2ZpSnFRNHl5Rlk1cTNSdnVsUS9teFltM1ZiNGY3aUhOQWdNQkFBR2dBREFOCkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQWtwZHFOb0paVnFDbVFwckpEK0pkSXBDMjlqeGd2cUNvbzRPSklnSWoKYUs1dng2bnoxSlFJV3hqZDY3YU1SWmZpZ3J5T2U0M2NwekhuMDJLTEJkNTVoUW1jZllaWkZMQ3NNTitMMTYvQwpqaUtwZmg3NXBkeGdWN1Q5d0d6SGtkVmp4RkJIUFdmVjZOMWUrMG5ZWUZMYjRvNEg4WXErWnFTb0lvaDNpaVpGClFaK1NYU3VyZ1FUakk5VnBzWVZtSkFNQkd3aWVZYlJ6aGoxeWNadVEzL0hwc2FFVFhwU2ZPckRGR0tNeTdsK1cKKy9NVk5vT0dwNG9uMU9RNjkwY2ZMcWdXVDJPbVB1UDRJOWRNdCtoYUxvck0rZi9jYUdsaWZXTTNpNUVmZWNLWAo3cVJLOWhmb20xVHdNZlhMZmpDWXUweW45cW5hWnREbkR3b2llTisxVkFxQjVBPT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUgUkVRVUVTVC0tLS0t"
	csr1, _ := StringToCSR(csr1Str)

	//errorDeviceById
	csr2Str := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ25EQ0NBWVFDQVFBd1Z6RUxNQWtHQTFVRUJoTUNSVk14Q2pBSUJnTlZCQWdNQVVFeENqQUlCZ05WQkFjTQpBVUV4Q2pBSUJnTlZCQW9NQVVFeENqQUlCZ05WQkFzTUFVRXhHREFXQmdOVkJBTU1EMlZ5Y205eVJHVjJhV05sClFubEpaRENDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFOVzV3Rm5YT25vb29SbGUKb09mcHNwZmVWRmJhZ3R5NzNaNnhSQ0R6ZXMxYVByUURPTjZ6OHhydGdjZDRKa0REMDFnbWNYLzArakUvdnkybwpKT015cGlJbGluVVQyMFhoM0ZxazV1OG5IeXIxSTI1L04rTGdQdmx6eHIyVjlaOGQ3Y0VkcjhzVXBqa3ptRDhICmo0QjVLN1pXTHd6NktGRW5aY3J2SWtzZHVJeEkxMDMvS2JGdjRWTi9WTndPeEpaVFFkMFRYdVU2RE0rRDcwWU4KZUxWcVovc0krdXluM3o5bXlhZ1FIS1ZkblgwSDltQ3ZOdVBQelNUTkxvaG1GNkRLSHhhV1d4NHQ3TzNMTnU3dQpCMmF2b2JmdnNBS1ljWER3SjgyTXNIMGkvRDZtaVBvUE1sL1lvZFM4d3VkZ2xMWUhobWc0VmlvdzJmQ0E0RmVkCnJ5Z1o3N0VDQXdFQUFhQUFNQTBHQ1NxR1NJYjNEUUVCQ3dVQUE0SUJBUUFzMFJqTS9qclJGem5FU3ljRXlsSjgKWlNZTjE1ODNJNzFUeXFXQWE2RkEwK1htYVlDSTgyWHVSL0owNjY1N2ZjTEhicG1hTExCYnJzRDN4MkJUa29VSgpQQzdDV25kVmUvOXllYkZRaFdkOWdwcVA2UHBOZW1TN3ZmZ0pOaXVXb3hXS2tJOWNzZEh5emNWV0hsRGhzZllJClp5NHM4dGwxNkJkTDVHRnlBbkdOdFhubEZlYkdYOVZCays1YlU2WkhlaVd5ejJ5OXcwM1Y1RnFZeEhRV1VaQzkKcTBHRWFHYTBUaGtWbVU4S2VTYUs4MXBjYWZTeW5HeVpPbkI4VzFmbEwzVEJBNGxJQ3VBTVJkcUo5UEsyTlZIegp6aUVOWUJYMDRVWGNPUzJDVHcwekVTanpIR1JUaUplYy9aS2swcVM0TGljNlRxN2RFb3Vtclh2Kzd3MHZJZ3RVCi0tLS0tRU5EIENFUlRJRklDQVRFIFJFUVVFU1QtLS0tLQoK"
	csr2, _ := StringToCSR(csr2Str)

	//errorLog
	csr3Str := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ2xUQ0NBWDBDQVFBd1VERUxNQWtHQTFVRUJoTUNSVk14Q2pBSUJnTlZCQWdNQVVFeENqQUlCZ05WQkFjTQpBVUV4Q2pBSUJnTlZCQW9NQVVFeENqQUlCZ05WQkFzTUFVRXhFVEFQQmdOVkJBTU1DR1Z5Y205eVRHOW5NSUlCCklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUExZDZvRXNWemlncHBpWERHdk5tZk9IMHYKNWlhZ1ZIZGw4MWNUNS9SZ0VXQWNvdnpFSDBrQXF2cEFVMjhvU2JsYU5tTHBFanFNZjVjWVFCZUFRU0J2R1lQYwo1bmFkQ0daSGIyczc2anF1cHlyOG90eWhRNG0zaVhoQUZaeXVwRENIYXFLcDFzZFA4Ni9UbE55Z281alJmUmJECnZoNjFqYlVwdDZaMFQ1cnZoTlhSN1NyWXdPV0NMOVFiaG5pNzZ1Z2FoMVpNTU5xVEpwQ2ZidWZvUVJ3eDlWaE0KeW9jdnNJOHVFNUtKOHlta3J4bnFMM2RoeWkvTTFpZE1KVzM0ZGF3WWdJa0l1VzNVa2Z6eEhqaW44UHQyYk5QOQpySDBiZ1g0WXg1bXQrNGtrK040eTk5bHVuQ0cvNXlhZVo3MnhaZGZSUFJGNGxvbjF5dzUyUndQc3pDSmxqUUlECkFRQUJvQUF3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUd2YVRjSkJ5UnpZaEtndm1Kc1ZPcllVS2k2cHU3Q0gKSFVtdWdQOUZPWURRNEl2aEZCQzhhSHIwTkplZXNLdElHdHhUZE45S0krUTIrVmdnbndkL1VPUXpVeXlmVk1IcQpvSzlDSTE1WTBPWlN0YVZPNURtdTNMMzBMZjMvOCsvd2Q5NTY1Q1BrY3JnNk5pYllCVHFwNTI0elVEN1NWUUwzCjIxL2lzT3pNVng1Tnh3YlBISDBVajRaNHUxbXBaUDFvSm5NeFdWYTd6MEJLaHJWdGo5Ri9qOER3dVB2elNRYjIKQjd0V3ZyUDhjc0E4cUFLM3phbXFxOXl0RjVpYWtmbVVLak9qdGhjcFcvdyt5eXJPbkJWbnNLanU1VkpsYnhrYwprV3JXblcxRDNqcFRsbWUzNkN5VlJOQk5OSjBSY2hLc3RSUEVVemVaYmdVUHVPdDVEUG5Od2pRPQotLS0tLUVORCBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0K"
	csr3, _ := StringToCSR(csr3Str)

	//errorUpdateStatus
	csr4Str := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ25qQ0NBWVlDQVFBd1dURUxNQWtHQTFVRUJoTUNSVk14Q2pBSUJnTlZCQWdNQVVFeENqQUlCZ05WQkFjTQpBVUV4Q2pBSUJnTlZCQW9NQVVFeENqQUlCZ05WQkFzTUFVRXhHakFZQmdOVkJBTU1FV1Z5Y205eVZYQmtZWFJsClUzUmhkSFZ6TUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUEzTG9jOW1zWVBBZmgKdEsyQlBRQXROQ25sUzhOTmVuVkpnakxpU21uUjNjb01iVE4wTjJ6TDVYblg1VkNCZWY4TndrTE9LdGtubkFpZQplWElNeFpaQkIxcFpML29QQmJ0TElZZUtESXM2UE5WZncvM3ZoNUw0VmkvU1JnWHhVbzdJaEVFQzY3M2lEUmRoCkc0N0trU29ZbXJvWVQ1Q3dUS3BVU3FlWDlpRGhUVWFvd1crbnY5MFkxajUwdU9oTTd2K01BaTE5Z1Z2Z2hjSWsKUlVNdEhqWVdOTm1vUlBsT0tDMXNWbWdCSlIxWS95RTJkUlJJZ3daZlZGM3d1YVRXRHdSUXkycG1LRzZrV1ZPbAoxL01WeDA2ZHh2d3pYSlFIUWtFb2N5VW9ONDVjdHNvSkxGNEVnWVVPM0JkQXR0a2x5bXo1NDRNSnozRnFzRk9rCjJ2ajM1QXNqcHdJREFRQUJvQUF3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUxMeW9aazNqOTN0VktZNXkrd3gKRGpITFBILzhqb2hRZjdiUCtGVEltSW13NVlqQTBiamJ3UXUrdGdxTC9MNTg1NWI2dks4SWJpZGVNdUFvOFpYQwpXRm9zaFVTMnFrQXEvaGZ1anU4aFpOK3hlSElZTTgwREptRnFlaTJhWGF0MUluQkVjOG90dEREcmJ6bEp1c0tpCk9nblVLaks3ckd6dWE0Z1JodGVLeVl5MEFtbWJ5TEZTYVpXc0lxUVNHcUkydFpYVkhyVjVzUDJuL0JTcHhwbVkKQS9jeTNaWEE3WHJwZHZSb2dUck44ZDRSaXlUdXpjNGJpYWpJVzFpT1o4ZUVhUGd2WEVKRzFUUEVtM0hRdHVZRQpsQ0owN2ZlTmpHRVYxUnhiVjR3STRocE5MbXY1YjJxNlF2RkU0WE5hc05QSUR0TmNwa1RMU3d2c2RsYTE2eEZPCk8zbz0KLS0tLS1FTkQgQ0VSVElGSUNBVEUgUkVRVUVTVC0tLS0tCg"
	csr4, _ := StringToCSR(csr4Str)

	//errorUpdateDeviceCertificateSerialNumberByID
	csr5Str := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ3VUQ0NBYUVDQVFBd2RERUxNQWtHQTFVRUJoTUNSVk14Q2pBSUJnTlZCQWdNQVVFeENqQUlCZ05WQkFjTQpBVUV4Q2pBSUJnTlZCQW9NQVVFeENqQUlCZ05WQkFzTUFVRXhOVEF6QmdOVkJBTU1MR1Z5Y205eVZYQmtZWFJsClJHVjJhV05sUTJWeWRHbG1hV05oZEdWVFpYSnBZV3hPZFcxaVpYSkNlVWxFTUlJQklqQU5CZ2txaGtpRzl3MEIKQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBdjVlT1BNdk5GNm0zaUZvM2NrQkFQbVdUZ1BCTEdwa0Z2WVJSQUEyZQpFYis1RHI3UFhORkNPdEluMUdUUFU3bXFrSUFPZkVoUEVtNXNqQ1VmN2dZL0xmRHhKdmlDYTB1WnhmQzB3WUJiCkx3VTMvR282bUNyWktWWUdqbktoK2RHNTZHN2JkZnpBbnNpZ1NINFhoaDVUbHArdXkxWVFhWG1scHhHUk5oZXIKY011ZEJGVGtXVWRCZDVPc2hFQjdiL0NqeFhqQjk2bUh5cjJFczl1VjlLNzJYR0duQTcwQzhMekJwejhTU0xHZAprY3BBR1cxeS9QYVZiRXpEaFFjU0hBOWJ1K01JMjJtMjFCZGxzUWRmb0I0Rm83UStwL3hKOXI4b1F2VUFWTEFRClZIRkEwZ3lXeStKT2ZQQk1MU2VrSlp1ME1sSE12cllzRDcwWUt6eE4vbnd0NlFJREFRQUJvQUF3RFFZSktvWkkKaHZjTkFRRUxCUUFEZ2dFQkFKSWJlZjg2eldkU3lRc1VUYTB0bjE1TmhTZUZjTEFCdE9PZFRZVmZaU1NPZDBWbQpyYlJFWGlqU0o2c2hQNkRTMFFWbGYxSExsWDhEVDBqMFdzNURmb3FqeWN2YWJLOW05MlYzWXZVSUhRdnJzV1djClg0TlF0aDlXNjlPeUt1TFhDYktlUVhyU29zVmFRYnZtbEJLNDRuK1NyVWszOWJsVnozckNQNmVXbFRxWFpDeW0KV2MybW9UUkRLaG9vYWx5anhhSXFKanJVZGdSUTgxVWt6QkpyZUNzUmtheGR1Z25NUVZsQndjODJYcTU3ZU9vUQpRR1JHVXZydW5TOUpxWm9xWE1pL0l4L09PUVFNRFBidjN2Ky93cnF5UWZ3U1pXNDF4RnhZL0hHZEx2L2NqRHVJCnVmaEJSR3Byc3V0LzByM210dEZtUHFMa1h5OTFxWk41cENBbkFxUT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUgUkVRVUVTVC0tLS0tCgo"
	csr5, _ := StringToCSR(csr5Str)

	//decommisioned
	csr6Str := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ21qQ0NBWUlDQVFBd1ZURUxNQWtHQTFVRUJoTUNSVk14Q2pBSUJnTlZCQWdNQVVFeENqQUlCZ05WQkFjTQpBVUV4Q2pBSUJnTlZCQW9NQVVFeENqQUlCZ05WQkFzTUFVRXhGakFVQmdOVkJBTU1EV1JsWTI5dGJXbHphVzl1ClpXUXdnZ0VpTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElCRHdBd2dnRUtBb0lCQVFDbXRoMHdvVnQxUjJpeDZNY2QKaS8zRWNNbUpkT1FHdldXR0F1N3J4cytmaFlqQjlSd2hLQU85elIrVXdkM2p4QTl2MXdOdGVqK0dZR3hNWFpQQQpNa2h3bHhQV3pOQnJ6ZWZXdkltZmZrSFlaTDV1N204cEFxUnJvaCsxdmpwTnUwZHFOQy9FdHNEdTM0OXEwRjdWCnNleUR0T2RnaG9VS2Q2a2pNYzNESHR2LzAzelZzM3hRNU1EQjhqMUhzeWhKOTA4TFhnMjVYV0szaEdxTERhQlUKK0JWcUM2YTdwSERUTWEzMVJuQk1mS3Qyd3ZUMytCNFNMS21ycnBGSFRMMXVhTmJnL0NRd0dRZ0xrem4vOE8zWgpValJWWGlYL0VwL0FzbjE1RTdUbTF3dm85NUo3OHdBSkJ2Qk5RWGsrei9KNENPZUNsS2YvNHlIaTRZenpacEpJCi9TNGxBZ01CQUFHZ0FEQU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUFFeDI3MGw3T3R1RlgxR1I3Q3piKzFHNHEKWFZtYkdCWmdHTEhTR1kxQ0RLOUNPdE14YjFicEdoUUZ5Y2t3K0J5ZUs2WmpnUmlHNjRwb3hIeUF1UEhKYURvdgptTHQ0NnQ2R3gveEJ5a1gvMkkvdTZjcEs2VTl5NWVKS0laVTYzckNrZHdsZHJmMjhoT3hNandOMXhwVnlhZURnCmtiRVV0Qk94N2kzdUhrVjJwOHU1bEozekZ5QlRXM2Zya3dJOEZVL3FvYmthWlpGUmRjUnN6UmpnWGszZEhFUWsKbXNzdkxza3crcm1lZ1lrekNmMS94Y3VRK2tnSTNzQlhncTdoZjBXTG5vQ1dTeGx1OFNxeWhlZ1NDdjBqYWI4TgppNzhPQUMySm9GV0FBTmh6QlN4bzBKenRmQzZwTWVBWG82TUlzRXppcTc2WE13SXpDOHovTVhNcytFelI0QT09Ci0tLS0tRU5EIENFUlRJRklDQVRFIFJFUVVFU1QtLS0tLQoKCgo"
	csr6, _ := StringToCSR(csr6Str)

	//provisioned
	csr7Str := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ21EQ0NBWUFDQVFBd1V6RUxNQWtHQTFVRUJoTUNSVk14Q2pBSUJnTlZCQWdNQVVFeENqQUlCZ05WQkFjTQpBVUV4Q2pBSUJnTlZCQW9NQVVFeENqQUlCZ05WQkFzTUFVRXhGREFTQmdOVkJBTU1DM0J5YjNacGMybHZibVZrCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBc29yTG5tNmk5czlHMTVmVkROS1UKdFhzanJmWGZRb3hWazBYTDA2bFkrZkIvSzgwa3ZTbjhQWGRGQzdreTVTK0JyUEtZdHNlS0xOTjZyYkpFUkVuVQpab3lmWkdPbkwveU90TTB6anA2V21NNmxpSGhqeDE0NENscDNKNE4xTDJHc3cwS25wMG5Ea2JxTERlMjJRTjlZCnNCNEVaVHlJcTlQUFpzNTAzbVNGL1RsZ2dIc0NocFI1NEFKa1VNNjBDbGtybFprOHdmYyt2U3pTeE45QVlxSGIKTjIwVUpnV1prOXVnekdTZWQvMDdpL2FXanFNWXcwb1RrQTJQbkNERW1JOVplUHFjaGFZTG9HZW5OaHJJSkNlcgowN1VrVHZMVGljdkhXeVZHdEIxVDV1RUo4NFZXZHhSUDJhWEJISEtQVFVGNXRJVm9qT1N1Yml5MG1uSDVGd0p5CkR3SURBUUFCb0FBd0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dFQkFIWjZNUWJSRTNWZHN6U3J2VXhEbXAwZXBnTTYKaURUcjRoMi9KbklpS1prcnROYXRrbWFiaVJjM1Vkd0p0V3JxRWNHOW5GdkpYQW9TNUdpTjhxeTRkeHRQSVVURwpMUGlwREhmdU10bU5KZTkxdHRiWFVSV0VaRkNPL2RSdFpzSFZocUNBai9OTWxtdzVTU3BKMTIrYzFKTDR4bm1RClRzVEhqTk5YMytSMmJrVE5pUVNyY3JVUXNmK1dCY21OSHR2aW42aVJZd29KbDQ2cmFhM3ZqQUFxa3o2cldkRG4KN1A4YUV4aVBoSCtnbitDbWxUWGx4cDhSZGtPdmxWSFcxN2xoQzVXNGtGaHlBUFJXNWZkaGlvREp0SEl5ZUZLaQpYMkxzL25RZEwySTNtZmtPNWVqOUdMTU5DZnVtaU02Um1PL2FwMDRObzJUOGsyeTBINXg4azJ2ei9naz0KLS0tLS1FTkQgQ0VSVElGSUNBVEUgUkVRVUVTVC0tLS0tCgoK"
	csr7, _ := StringToCSR(csr7Str)

	testCases := []struct {
		name string
		csr  *x509.CertificateRequest
		ret  error
	}{
		{"Correct", csr1, nil},
		{"Error Insert Log", csr3, errors.New("Could not insert log")},
		{"Error finding device", csr2, errors.New("Could not find device by Id")},
		{"Error Insert Device Cert History", csr1, errors.New("Testing DB connection failed")},
		{"Error Update Status By Id", csr4, errors.New("error")},
		{"Error Update Device Certificate Serial Number By ID", csr5, errors.New("error")},
		{"Error Decommisioned Device", csr6, errors.New("cant issue a certificate for a decommisioned device")},
		{"Error Provisioned Device", csr7, errors.New("The device (provisioned) already has a valid certificate")},
		{"Error Sign Certificate RequestFail", csr1, errors.New("validation error: Error revoking certificate")},
	}

	for _, tc := range testCases {

		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {

			if tc.name == "Error Insert Device Cert History" {
				ctx = context.WithValue(ctx, "DBInsertDeviceCertHistory", true)
				ctx = context.WithValue(ctx, "SignCertificateRequestFail", false)
				ctx = context.WithValue(ctx, "DBInsertLog", false)
			} else if tc.name == "Error Sign Certificate RequestFail" {
				ctx = context.WithValue(ctx, "DBInsertDeviceCertHistory", false)
				ctx = context.WithValue(ctx, "SignCertificateRequestFail", true)
				ctx = context.WithValue(ctx, "DBInsertLog", false)
			} else if tc.name == "Error Insert Log" {
				ctx = context.WithValue(ctx, "DBInsertDeviceCertHistory", false)
				ctx = context.WithValue(ctx, "SignCertificateRequestFail", false)
				ctx = context.WithValue(ctx, "DBInsertLog", true)
			} else {
				ctx = context.WithValue(ctx, "DBInsertDeviceCertHistory", false)
				ctx = context.WithValue(ctx, "SignCertificateRequestFail", false)
				ctx = context.WithValue(ctx, "DBInsertLog", false)
			}

			snInt := new(big.Int)
			snInt, _ = snInt.SetString("15898402459309774930443891423546184692", 10)
			/*template := x509.Certificate{
				SerialNumber: snInt,
				Subject: pkix.Name{
					Organization: []string{"Acme Co"},
				},
				NotBefore: time.Now(),
				NotAfter:  time.Now().Add(time.Hour * 24 * 180),

				KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
				ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				BasicConstraintsValid: true,
			}*/

			// derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
			certContent, err := ioutil.ReadFile("/home/ikerlan/lamassu/lamassuiot/nogit/dms.crt")
			cpb, _ := pem.Decode(certContent)
			dmsCrt, err := x509.ParseCertificate(cpb.Bytes)

			_, err = srv.Enroll(ctx, tc.csr, "IkerCA", dmsCrt)
			if err != nil {
				if tc.ret.Error() != err.Error() {
					t.Errorf("Got result is %s; want %s", err, tc.ret)
				}
			}
		})
	}
}

func TestServerKeyGen(t *testing.T) {
	srv, ctx := setup(t)

	csr1Str := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ2pqQ0NBWFlDQVFBd1NURUxNQWtHQTFVRUJoTUNSVk14Q2pBSUJnTlZCQWdNQVVFeENqQUlCZ05WQkFjTQpBVUV4Q2pBSUJnTlZCQW9NQVVFeENqQUlCZ05WQkFzTUFVRXhDakFJQmdOVkJBTU1BVEV3Z2dFaU1BMEdDU3FHClNJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUUN4ODkxSkZFTnpzOHdQc1RVQ2tGS0pmYWxBSGd4bklBZkYKRkNmWUJGUk44bU84T1FsNXlmV1MyWk5ub3p2NnpPblBGNFpvMGkwVldocGFhSTZtdWxpOEl6Y2cwdDMxdzllQwo4U2NBTnJQNFFJeDluR3NXV3pVNWk2NnZydzZrMWhQV0k5eDh1V0VoeW1tcFlRaEVuT2tzWHQvYXZISmppZzA1ClJQSDdkWk45UXhoaTF0WXl4N0ZSUUNadE02SFV2SGpTalFFc25rRUJkSTBaVWZkMlpTWmo2NGlCbTJ0RXkvVUoKL0NuUGJkR01PbUloZHhqY2Zva0RtTjkrdTZKT2NyYWtrT204aXhrRHlvTGtEWVUrVllOelROZmNSUVR5R0IvZgpUMDJEMEdLWUZOKy9FZ09vR0tuU2ZpSnFRNHl5Rlk1cTNSdnVsUS9teFltM1ZiNGY3aUhOQWdNQkFBR2dBREFOCkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQWtwZHFOb0paVnFDbVFwckpEK0pkSXBDMjlqeGd2cUNvbzRPSklnSWoKYUs1dng2bnoxSlFJV3hqZDY3YU1SWmZpZ3J5T2U0M2NwekhuMDJLTEJkNTVoUW1jZllaWkZMQ3NNTitMMTYvQwpqaUtwZmg3NXBkeGdWN1Q5d0d6SGtkVmp4RkJIUFdmVjZOMWUrMG5ZWUZMYjRvNEg4WXErWnFTb0lvaDNpaVpGClFaK1NYU3VyZ1FUakk5VnBzWVZtSkFNQkd3aWVZYlJ6aGoxeWNadVEzL0hwc2FFVFhwU2ZPckRGR0tNeTdsK1cKKy9NVk5vT0dwNG9uMU9RNjkwY2ZMcWdXVDJPbVB1UDRJOWRNdCtoYUxvck0rZi9jYUdsaWZXTTNpNUVmZWNLWAo3cVJLOWhmb20xVHdNZlhMZmpDWXUweW45cW5hWnREbkR3b2llTisxVkFxQjVBPT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUgUkVRVUVTVC0tLS0t"
	csr1, _ := StringToCSR(csr1Str)

	//errorDeviceById

	csr2Str := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ25EQ0NBWVFDQVFBd1Z6RUxNQWtHQTFVRUJoTUNSVk14Q2pBSUJnTlZCQWdNQVVFeENqQUlCZ05WQkFjTQpBVUV4Q2pBSUJnTlZCQW9NQVVFeENqQUlCZ05WQkFzTUFVRXhHREFXQmdOVkJBTU1EMlZ5Y205eVJHVjJhV05sClFubEpaRENDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFOVzV3Rm5YT25vb29SbGUKb09mcHNwZmVWRmJhZ3R5NzNaNnhSQ0R6ZXMxYVByUURPTjZ6OHhydGdjZDRKa0REMDFnbWNYLzArakUvdnkybwpKT015cGlJbGluVVQyMFhoM0ZxazV1OG5IeXIxSTI1L04rTGdQdmx6eHIyVjlaOGQ3Y0VkcjhzVXBqa3ptRDhICmo0QjVLN1pXTHd6NktGRW5aY3J2SWtzZHVJeEkxMDMvS2JGdjRWTi9WTndPeEpaVFFkMFRYdVU2RE0rRDcwWU4KZUxWcVovc0krdXluM3o5bXlhZ1FIS1ZkblgwSDltQ3ZOdVBQelNUTkxvaG1GNkRLSHhhV1d4NHQ3TzNMTnU3dQpCMmF2b2JmdnNBS1ljWER3SjgyTXNIMGkvRDZtaVBvUE1sL1lvZFM4d3VkZ2xMWUhobWc0VmlvdzJmQ0E0RmVkCnJ5Z1o3N0VDQXdFQUFhQUFNQTBHQ1NxR1NJYjNEUUVCQ3dVQUE0SUJBUUFzMFJqTS9qclJGem5FU3ljRXlsSjgKWlNZTjE1ODNJNzFUeXFXQWE2RkEwK1htYVlDSTgyWHVSL0owNjY1N2ZjTEhicG1hTExCYnJzRDN4MkJUa29VSgpQQzdDV25kVmUvOXllYkZRaFdkOWdwcVA2UHBOZW1TN3ZmZ0pOaXVXb3hXS2tJOWNzZEh5emNWV0hsRGhzZllJClp5NHM4dGwxNkJkTDVHRnlBbkdOdFhubEZlYkdYOVZCays1YlU2WkhlaVd5ejJ5OXcwM1Y1RnFZeEhRV1VaQzkKcTBHRWFHYTBUaGtWbVU4S2VTYUs4MXBjYWZTeW5HeVpPbkI4VzFmbEwzVEJBNGxJQ3VBTVJkcUo5UEsyTlZIegp6aUVOWUJYMDRVWGNPUzJDVHcwekVTanpIR1JUaUplYy9aS2swcVM0TGljNlRxN2RFb3Vtclh2Kzd3MHZJZ3RVCi0tLS0tRU5EIENFUlRJRklDQVRFIFJFUVVFU1QtLS0tLQoK"
	csr2, _ := StringToCSR(csr2Str)

	//errorLog
	csr3Str := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ2xUQ0NBWDBDQVFBd1VERUxNQWtHQTFVRUJoTUNSVk14Q2pBSUJnTlZCQWdNQVVFeENqQUlCZ05WQkFjTQpBVUV4Q2pBSUJnTlZCQW9NQVVFeENqQUlCZ05WQkFzTUFVRXhFVEFQQmdOVkJBTU1DR1Z5Y205eVRHOW5NSUlCCklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFwbEFjcEdoaWlXK0FFR2xyWWFSdW5QbnEKSzF2YnNQMW56NFhkcm04N3htb3Q3NjJVVXdtK0o3c3NybDh5eFRhY1M2RzduTFFOYU9kemJPRnRsZnB0ekNTQgoxalRyM0pJR2ZqNVErYUFyeTVOQXRWa1g1bm15ZW5XckhrOXVhSUZVOWRHZnBmTXhTbld3aFRSRk5iN1l5QWlsCndISUY5Wm4wT3EvcnhuMkZCTE0zU2VQTmIwMytZZlE5T0VmQnBGZEl1bThLemNDc0l2S2o2azF0cWxhZ0VCek0KWVpmMEJsdFhjZ2VzZUJDQ0dzTEZDOHM4dmFoR0llUjdNVkRXSnIxMHphR1JnK2EvVXd3cTJ0dFhmS2IyZ3NkSQoxb1hCdTRrSVJrMGRBQ284OTIxQTBna29BSHBRS1RWeTNrNk9XYjBvVWRRL25IYTU2SFZHOU50RWxVZTBHd0lECkFRQUJvQUF3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUlNNnBsK0RsOTN2cytIdnlqZzJoam1WREhPVnB4ZlYKVFUrcDNFRVNYdVdZeHNLV09NWTRvZzVHM2F4RWcxYXBNQTZseG9FdCsramxSa016djZCTFdaMmFyc2tMbjUveQplVnZuNnFyWHNXelFEbWt1UndoTkVwVTlUQWVrV0g5UGZNVDNrckdaVnVBdzRKOUw5UXEzZWhQL0wxVC9iMlVYCi9KMVQvUzRrRFBpWktVYXk5SnRrMWt6d2pxdFVEOGkwRmM4UU44VEV0Y0l0ZTFXZFR0bHpvaGJSc3NxSzJUUHgKMm1GTkVoa2lpQjQwcVdzQUtZL0dBSVc0Y1ZCWWd3ME5CU0s2OGlUeUticzdBM1NsOGZmQnFsYmswa1FnYWo1YQo2L0NjVVlkc3BMMlhJeFRlZ2hicUNCUFpIUW1mTHNtWkcwQW1lbEo3QWFQei9obWdYcHJoUnBvPQotLS0tLUVORCBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0K"
	csr3, _ := StringToCSR(csr3Str)

	//errorUpdateStatus
	csr4Str := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ25qQ0NBWVlDQVFBd1dURUxNQWtHQTFVRUJoTUNSVk14Q2pBSUJnTlZCQWdNQVVFeENqQUlCZ05WQkFjTQpBVUV4Q2pBSUJnTlZCQW9NQVVFeENqQUlCZ05WQkFzTUFVRXhHakFZQmdOVkJBTU1FV1Z5Y205eVZYQmtZWFJsClUzUmhkSFZ6TUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUEzTG9jOW1zWVBBZmgKdEsyQlBRQXROQ25sUzhOTmVuVkpnakxpU21uUjNjb01iVE4wTjJ6TDVYblg1VkNCZWY4TndrTE9LdGtubkFpZQplWElNeFpaQkIxcFpML29QQmJ0TElZZUtESXM2UE5WZncvM3ZoNUw0VmkvU1JnWHhVbzdJaEVFQzY3M2lEUmRoCkc0N0trU29ZbXJvWVQ1Q3dUS3BVU3FlWDlpRGhUVWFvd1crbnY5MFkxajUwdU9oTTd2K01BaTE5Z1Z2Z2hjSWsKUlVNdEhqWVdOTm1vUlBsT0tDMXNWbWdCSlIxWS95RTJkUlJJZ3daZlZGM3d1YVRXRHdSUXkycG1LRzZrV1ZPbAoxL01WeDA2ZHh2d3pYSlFIUWtFb2N5VW9ONDVjdHNvSkxGNEVnWVVPM0JkQXR0a2x5bXo1NDRNSnozRnFzRk9rCjJ2ajM1QXNqcHdJREFRQUJvQUF3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUxMeW9aazNqOTN0VktZNXkrd3gKRGpITFBILzhqb2hRZjdiUCtGVEltSW13NVlqQTBiamJ3UXUrdGdxTC9MNTg1NWI2dks4SWJpZGVNdUFvOFpYQwpXRm9zaFVTMnFrQXEvaGZ1anU4aFpOK3hlSElZTTgwREptRnFlaTJhWGF0MUluQkVjOG90dEREcmJ6bEp1c0tpCk9nblVLaks3ckd6dWE0Z1JodGVLeVl5MEFtbWJ5TEZTYVpXc0lxUVNHcUkydFpYVkhyVjVzUDJuL0JTcHhwbVkKQS9jeTNaWEE3WHJwZHZSb2dUck44ZDRSaXlUdXpjNGJpYWpJVzFpT1o4ZUVhUGd2WEVKRzFUUEVtM0hRdHVZRQpsQ0owN2ZlTmpHRVYxUnhiVjR3STRocE5MbXY1YjJxNlF2RkU0WE5hc05QSUR0TmNwa1RMU3d2c2RsYTE2eEZPCk8zbz0KLS0tLS1FTkQgQ0VSVElGSUNBVEUgUkVRVUVTVC0tLS0tCg"
	csr4, _ := StringToCSR(csr4Str)

	//errorUpdateDeviceCertificateSerialNumberByID
	csr5Str := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ3VUQ0NBYUVDQVFBd2RERUxNQWtHQTFVRUJoTUNSVk14Q2pBSUJnTlZCQWdNQVVFeENqQUlCZ05WQkFjTQpBVUV4Q2pBSUJnTlZCQW9NQVVFeENqQUlCZ05WQkFzTUFVRXhOVEF6QmdOVkJBTU1MR1Z5Y205eVZYQmtZWFJsClJHVjJhV05sUTJWeWRHbG1hV05oZEdWVFpYSnBZV3hPZFcxaVpYSkNlVWxFTUlJQklqQU5CZ2txaGtpRzl3MEIKQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBdjVlT1BNdk5GNm0zaUZvM2NrQkFQbVdUZ1BCTEdwa0Z2WVJSQUEyZQpFYis1RHI3UFhORkNPdEluMUdUUFU3bXFrSUFPZkVoUEVtNXNqQ1VmN2dZL0xmRHhKdmlDYTB1WnhmQzB3WUJiCkx3VTMvR282bUNyWktWWUdqbktoK2RHNTZHN2JkZnpBbnNpZ1NINFhoaDVUbHArdXkxWVFhWG1scHhHUk5oZXIKY011ZEJGVGtXVWRCZDVPc2hFQjdiL0NqeFhqQjk2bUh5cjJFczl1VjlLNzJYR0duQTcwQzhMekJwejhTU0xHZAprY3BBR1cxeS9QYVZiRXpEaFFjU0hBOWJ1K01JMjJtMjFCZGxzUWRmb0I0Rm83UStwL3hKOXI4b1F2VUFWTEFRClZIRkEwZ3lXeStKT2ZQQk1MU2VrSlp1ME1sSE12cllzRDcwWUt6eE4vbnd0NlFJREFRQUJvQUF3RFFZSktvWkkKaHZjTkFRRUxCUUFEZ2dFQkFKSWJlZjg2eldkU3lRc1VUYTB0bjE1TmhTZUZjTEFCdE9PZFRZVmZaU1NPZDBWbQpyYlJFWGlqU0o2c2hQNkRTMFFWbGYxSExsWDhEVDBqMFdzNURmb3FqeWN2YWJLOW05MlYzWXZVSUhRdnJzV1djClg0TlF0aDlXNjlPeUt1TFhDYktlUVhyU29zVmFRYnZtbEJLNDRuK1NyVWszOWJsVnozckNQNmVXbFRxWFpDeW0KV2MybW9UUkRLaG9vYWx5anhhSXFKanJVZGdSUTgxVWt6QkpyZUNzUmtheGR1Z25NUVZsQndjODJYcTU3ZU9vUQpRR1JHVXZydW5TOUpxWm9xWE1pL0l4L09PUVFNRFBidjN2Ky93cnF5UWZ3U1pXNDF4RnhZL0hHZEx2L2NqRHVJCnVmaEJSR3Byc3V0LzByM210dEZtUHFMa1h5OTFxWk41cENBbkFxUT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUgUkVRVUVTVC0tLS0tCgo"
	csr5, _ := StringToCSR(csr5Str)

	//decommisioned
	csr6Str := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ21qQ0NBWUlDQVFBd1ZURUxNQWtHQTFVRUJoTUNSVk14Q2pBSUJnTlZCQWdNQVVFeENqQUlCZ05WQkFjTQpBVUV4Q2pBSUJnTlZCQW9NQVVFeENqQUlCZ05WQkFzTUFVRXhGakFVQmdOVkJBTU1EV1JsWTI5dGJXbHphVzl1ClpXUXdnZ0VpTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElCRHdBd2dnRUtBb0lCQVFDbXRoMHdvVnQxUjJpeDZNY2QKaS8zRWNNbUpkT1FHdldXR0F1N3J4cytmaFlqQjlSd2hLQU85elIrVXdkM2p4QTl2MXdOdGVqK0dZR3hNWFpQQQpNa2h3bHhQV3pOQnJ6ZWZXdkltZmZrSFlaTDV1N204cEFxUnJvaCsxdmpwTnUwZHFOQy9FdHNEdTM0OXEwRjdWCnNleUR0T2RnaG9VS2Q2a2pNYzNESHR2LzAzelZzM3hRNU1EQjhqMUhzeWhKOTA4TFhnMjVYV0szaEdxTERhQlUKK0JWcUM2YTdwSERUTWEzMVJuQk1mS3Qyd3ZUMytCNFNMS21ycnBGSFRMMXVhTmJnL0NRd0dRZ0xrem4vOE8zWgpValJWWGlYL0VwL0FzbjE1RTdUbTF3dm85NUo3OHdBSkJ2Qk5RWGsrei9KNENPZUNsS2YvNHlIaTRZenpacEpJCi9TNGxBZ01CQUFHZ0FEQU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUFFeDI3MGw3T3R1RlgxR1I3Q3piKzFHNHEKWFZtYkdCWmdHTEhTR1kxQ0RLOUNPdE14YjFicEdoUUZ5Y2t3K0J5ZUs2WmpnUmlHNjRwb3hIeUF1UEhKYURvdgptTHQ0NnQ2R3gveEJ5a1gvMkkvdTZjcEs2VTl5NWVKS0laVTYzckNrZHdsZHJmMjhoT3hNandOMXhwVnlhZURnCmtiRVV0Qk94N2kzdUhrVjJwOHU1bEozekZ5QlRXM2Zya3dJOEZVL3FvYmthWlpGUmRjUnN6UmpnWGszZEhFUWsKbXNzdkxza3crcm1lZ1lrekNmMS94Y3VRK2tnSTNzQlhncTdoZjBXTG5vQ1dTeGx1OFNxeWhlZ1NDdjBqYWI4TgppNzhPQUMySm9GV0FBTmh6QlN4bzBKenRmQzZwTWVBWG82TUlzRXppcTc2WE13SXpDOHovTVhNcytFelI0QT09Ci0tLS0tRU5EIENFUlRJRklDQVRFIFJFUVVFU1QtLS0tLQoKCgo"
	csr6, _ := StringToCSR(csr6Str)

	//provisioned
	csr7Str := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ21EQ0NBWUFDQVFBd1V6RUxNQWtHQTFVRUJoTUNSVk14Q2pBSUJnTlZCQWdNQVVFeENqQUlCZ05WQkFjTQpBVUV4Q2pBSUJnTlZCQW9NQVVFeENqQUlCZ05WQkFzTUFVRXhGREFTQmdOVkJBTU1DM0J5YjNacGMybHZibVZrCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBc29yTG5tNmk5czlHMTVmVkROS1UKdFhzanJmWGZRb3hWazBYTDA2bFkrZkIvSzgwa3ZTbjhQWGRGQzdreTVTK0JyUEtZdHNlS0xOTjZyYkpFUkVuVQpab3lmWkdPbkwveU90TTB6anA2V21NNmxpSGhqeDE0NENscDNKNE4xTDJHc3cwS25wMG5Ea2JxTERlMjJRTjlZCnNCNEVaVHlJcTlQUFpzNTAzbVNGL1RsZ2dIc0NocFI1NEFKa1VNNjBDbGtybFprOHdmYyt2U3pTeE45QVlxSGIKTjIwVUpnV1prOXVnekdTZWQvMDdpL2FXanFNWXcwb1RrQTJQbkNERW1JOVplUHFjaGFZTG9HZW5OaHJJSkNlcgowN1VrVHZMVGljdkhXeVZHdEIxVDV1RUo4NFZXZHhSUDJhWEJISEtQVFVGNXRJVm9qT1N1Yml5MG1uSDVGd0p5CkR3SURBUUFCb0FBd0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dFQkFIWjZNUWJSRTNWZHN6U3J2VXhEbXAwZXBnTTYKaURUcjRoMi9KbklpS1prcnROYXRrbWFiaVJjM1Vkd0p0V3JxRWNHOW5GdkpYQW9TNUdpTjhxeTRkeHRQSVVURwpMUGlwREhmdU10bU5KZTkxdHRiWFVSV0VaRkNPL2RSdFpzSFZocUNBai9OTWxtdzVTU3BKMTIrYzFKTDR4bm1RClRzVEhqTk5YMytSMmJrVE5pUVNyY3JVUXNmK1dCY21OSHR2aW42aVJZd29KbDQ2cmFhM3ZqQUFxa3o2cldkRG4KN1A4YUV4aVBoSCtnbitDbWxUWGx4cDhSZGtPdmxWSFcxN2xoQzVXNGtGaHlBUFJXNWZkaGlvREp0SEl5ZUZLaQpYMkxzL25RZEwySTNtZmtPNWVqOUdMTU5DZnVtaU02Um1PL2FwMDRObzJUOGsyeTBINXg4azJ2ei9naz0KLS0tLS1FTkQgQ0VSVElGSUNBVEUgUkVRVUVTVC0tLS0tCgoK"
	csr7, _ := StringToCSR(csr7Str)

	testCases := []struct {
		name string
		csr  *x509.CertificateRequest
		ret  error
	}{
		{"Correct", csr1, nil},
		{"Error finding device", csr2, errors.New("Could not find device by Id")},
		{"Error Insert Log", csr3, errors.New("Could not insert log")},
		{"Error Insert Device Cert History", csr1, errors.New("Testing DB connection failed")},
		{"Error Update Status By Id", csr4, errors.New("error")},
		{"Error Update Device Certificate Serial Number By ID", csr5, errors.New("error")},
		{"Error Decommisioned Device", csr6, errors.New("cant issue a certificate for a decommisioned device")},
		{"Error Provisioned Device", csr7, errors.New("The device (provisioned) already has a valid certificate")},
		{"Error Sign Certificate RequestFail", csr1, errors.New("validation error: Error revoking certificate")},
	}

	for _, tc := range testCases {

		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {

			if tc.name == "Error Insert Device Cert History" {
				ctx = context.WithValue(ctx, "DBInsertDeviceCertHistory", true)
				ctx = context.WithValue(ctx, "SignCertificateRequestFail", false)
				ctx = context.WithValue(ctx, "DBInsertLog", false)
			} else if tc.name == "Error Insert Log" {
				ctx = context.WithValue(ctx, "DBInsertDeviceCertHistory", false)
				ctx = context.WithValue(ctx, "SignCertificateRequestFail", false)
				ctx = context.WithValue(ctx, "DBInsertLog", true)
			} else if tc.name == "Error Sign Certificate RequestFail" {
				ctx = context.WithValue(ctx, "DBInsertDeviceCertHistory", false)
				ctx = context.WithValue(ctx, "SignCertificateRequestFail", true)
				ctx = context.WithValue(ctx, "DBInsertLog", false)
			} else {
				ctx = context.WithValue(ctx, "DBInsertDeviceCertHistory", false)
				ctx = context.WithValue(ctx, "SignCertificateRequestFail", false)
				ctx = context.WithValue(ctx, "DBInsertLog", false)
			}
			snInt := new(big.Int)
			snInt, _ = snInt.SetString("15898402459309774930443891423546184692", 10)

			certContent, _ := ioutil.ReadFile("/home/ikerlan/lamassu/lamassuiot/nogit/dms.crt")
			cpb, _ := pem.Decode(certContent)
			dmsCrt, _ := x509.ParseCertificate(cpb.Bytes)

			_, _, err := srv.ServerKeyGen(ctx, tc.csr, "IkerCA", dmsCrt)
			if err != nil {
				if tc.ret.Error() != err.Error() {
					t.Errorf("Got result is %s; want %s", err, tc.ret)
				}

			}
		})
	}

}

func TestHealth(t *testing.T) {
	srv, ctx := setup(t)
	type testCasesHealth struct {
		name string
		ret  bool
	}
	cases := []testCasesHealth{
		{"Correct", true},
	}
	for _, tc := range cases {

		out := srv.Health(ctx)
		if tc.ret != out {
			t.Errorf("Expected '%s', but got '%s'", strconv.FormatBool(tc.ret), strconv.FormatBool(out))
		}

	}
}

func TestCACerts(t *testing.T) {
	srv, ctx := setup(t)

	testCases := []struct {
		name string
		aps  string
		http *http.Request
		ret  error
	}{
		{"Empty request", "", nil, nil},
		{"Error getting CAs", "", nil, errors.New("validation error: Error in client request")},
	}

	for _, tc := range testCases {

		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {

			if tc.name == "Error getting CAs" {
				ctx = context.WithValue(ctx, "DBShouldFail", true)
			} else {
				ctx = context.WithValue(ctx, "DBShouldFail", false)
			}
			_, err := srv.CACerts(ctx, tc.aps)
			if err != nil {
				if tc.ret.Error() != err.Error() {
					t.Errorf("Got result is %s; want %s", err, tc.ret)
				}

			}
		})
	}
}

func setup(t *testing.T) (EstServiceI, context.Context) {
	t.Helper()

	buf := &bytes.Buffer{}
	logger := log.NewJSONLogger(buf)
	ctx := context.Background()
	ctx = context.WithValue(ctx, utils.LamassuLoggerContextKey, logger)

	devicesDb, _ := mocks.NewDevicedDBMock(t)
	dmsDB, _ := mocks.NewDmsDBMock(t)

	lamassuCaClient, _ := mocks.NewLamassuCaClientMock(logger)
	verify := verify.NewUtils(&lamassuCaClient, logger)

	srv := NewEstService(&lamassuCaClient, &verify, devicesDb, dmsDB, 2, logger)
	return srv, ctx
}

func testCA() *x509.Certificate {
	CA := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZtVENDQTRHZ0F3SUJBZ0lVSG1yc3dnVms3MlZtZjF1dWU3UVZKUm5vTEljd0RRWUpLb1pJaHZjTkFRRUwKQlFBd1hERUxNQWtHQTFVRUJoTUNSVk14RVRBUEJnTlZCQWdNQ0VkcGNIVjZhMjloTVJFd0R3WURWUVFIREFoQgpjbkpoYzJGMFpURU1NQW9HQTFVRUNnd0RTVXRNTVF3d0NnWURWUVFMREFOYVVFUXhDekFKQmdOVkJBTU1Ba05CCk1CNFhEVEl5TURJeE5qRXhORGd4TTFvWERUSXpNREl4TmpFeE5EZ3hNMW93WERFTE1Ba0dBMVVFQmhNQ1JWTXgKRVRBUEJnTlZCQWdNQ0VkcGNIVjZhMjloTVJFd0R3WURWUVFIREFoQmNuSmhjMkYwWlRFTU1Bb0dBMVVFQ2d3RApTVXRNTVF3d0NnWURWUVFMREFOYVVFUXhDekFKQmdOVkJBTU1Ba05CTUlJQ0lqQU5CZ2txaGtpRzl3MEJBUUVGCkFBT0NBZzhBTUlJQ0NnS0NBZ0VBbWhONFVIdnRUcTVyelhXN01ibzltNTRicXRoeVlvdlNOODZmWkxFN0FqS3gKSVVpU0JCSVFUZkwyWVdqdXB5NFFBR0ZhU085WXk1Q1MvOVV1MWZTYTkrcFJ1QmVBZ1hVSTVzcXhlZEN6WEtScgpPT0R3L1I0dGkydVJUUEpzZWJ2K3l3MUswd3Z0R00yTXlLYTMyNFRMZnQ5UE05Nlc5VWsrOHlYc1dYQlo2Z1g4CnQ5cHJydkFrWkNRUlhDbTZ5amg1RWRIb2QxRy82TU95Y0RMVVN6RGhwcVpHaFVjTnl0RUxiOHA2ZGllNTRPOVoKWlB3TDl2QmpWemNROHo0WDBiWi9RbFJUcWhIQXJxUUxHaG02TTlTdkxUM0hLU1NoL1BpU2JhODk1V3h0OGJNMAo0Um9zYy96aDN3eVVSZVV1SFdQZm9uQWFGWjAxNFJCQ1Bud3Zub0dVeW8xRDIreWxncnhqRkJOQndzbm0rU1NPClVnN09JU05XaDRHK1RYa2JrK1RSajEvV0RGV2lDcC8wdmlacS95ZE02WWJNRHp2eWl0NWhsUnBxNXpYTzVFZi8KYlZmbVk0RXd2Ukx2RkVkNE1SelI2SWQrRjB4UWd1MFFWWmYwZHdGVU12V2Q2dUZOa3NSbDl2Z3hiNmZyQVFHbgp1VkVvTnVBN1VUZ1NCOVA5aXFKY2tBMFhacjQyaEcwYUw2b0FPdUxYZHU0azFkcm5ZMzRwdFhPRGNuRjBBMWl2ClV6SFhCNm9UNlRhSk5hQUlRVm5ETWJhWkRjcldGdmpVam9TNU45L2crQlRmVW42dWV1U3MzaTk5cHlZWTJ2Z24KVDFyV2xHUng2azQ5V2tBajQ3OG1wdFd6K01VeFJJVkl5bFlCNmxlMGUvMHlLR3FuZWd1R3Z4N0JjanhqTVhFQwpBd0VBQWFOVE1GRXdIUVlEVlIwT0JCWUVGQjNTNkE5NTQzT21oaTNhVFpYQVM2VjRiRjlKTUI4R0ExVWRJd1FZCk1CYUFGQjNTNkE5NTQzT21oaTNhVFpYQVM2VjRiRjlKTUE4R0ExVWRFd0VCL3dRRk1BTUJBZjh3RFFZSktvWkkKaHZjTkFRRUxCUUFEZ2dJQkFGdHFRVEZUNGozcmUwanJrSjZBUDBrMk0raWhYall0MVk1c0ZvbWNaY2pFaWVKcApETDJDam04WEdnRWNHdkp6K01oSDY1T2hITHZIRU9tbjkvckcwWStsTzhhYmhTQ1pIZWVqYWRLNEFSSlhHSlQ3CkZPRVBDNjgrRVl5SG9wai8xUmRCSXhjMkN4WFFwOC9IYzA2bDVOUTBZS3ZmYW5vM0ZGSFZEN09YT2tQSTVNSWcKN1JDOWVNL2Z4NlVyaHNhVTNERzlMcVBxNEMzcFFmRnEvTHBublBnYjRsbmlRQVZ0ZXRoWWhNSHFDUHdMMVJvQQoxTmdUZmJrWjBQaDl6N2cySUF4MW9SOXo5dWk0WWRWOVpycjhQTDBPaG4zM3BPbFJrZDNUcWJiY3FWcHBEL282CmFYZlJVU2taQWhoMXg4MlpzN2U2b2x4ekNTc3p0KzhUOTRtU0I5OWRoSDJiVnh4RWpPb3cvSklwNnlMT2JnUGcKdjZaRzROMEVaU2JlSGRzZ2ovbTd6RHg5Tlk2WGkrTUpidGlZdkRrdWpnRjdPanpVZkF3TUFaRzdOR0YraDNMWgpKb2EzQUg0ZDQ2UjFRVXRLQTdmUEpVb0pTb0xTVDZSOW9PR3dacUEzK1p6dDd4VFNoZkc2VDY0OWYxZ2c3OFhoCmRtM3hRYjZERUQvYk1iY3hGZUlvUW0yTklBS3VyUkMrV0hCMXFpZWlEdnZNd21IdjZGNHlvVWpNWEsyQVdWZysKWEJmb01KejZTYWZaOFlBWEhyVWdCdG8rVi95WTNaZzErOWdva0ZIOUkySHRFK1dOeUZjdUc3NEFoWlNMUHdiVgpwaE1FQUhHeTZVZWZaWlVpRTJ4SHFZRElDbVlWUlBUNGdrWlNqTXFKRDZ6ZExWTUNLcG81RnFXbEdvZEQKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQ=="
	CACert, _ := StringToCert(CA)
	return CACert
	/*
		serialNumber := "23-33-5b-19-c8-ed-8b-2a-92-5c-7b-57-fc-47-45-e7-12-03-91-23"

		keyMetadata := secrets.KeyInfo{
			KeyType:     "rsa",
			KeyBits:     4096,
			KeyStrength: "",
		}

		subject := secrets.Subject{
			C:  "ES",
			ST: "Gipuzkoa",
			L:  "Locality",
			O:  "Organization",
			OU: "OrganizationalUnit",
			CN: "CommonName",
		}

		certContent := secrets.CertContent{
			CerificateBase64: "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNURENDQWZPZ0F3SUJBZ0lVZnRXcTVObnpXZHUrSHk2S1RTMmpWazcybzRjd0NnWUlLb1pJemowRUF3SXcKY3pFTE1Ba0dBMVVFQmhNQ1JWTXhFVEFQQmdOVkJBZ1RDRWRwY0hWNmEyOWhNUkV3RHdZRFZRUUhFd2hCY25KaApjMkYwWlRFaE1BNEdBMVVFQ2hNSFV5NGdRMjl2Y0RBUEJnTlZCQW9UQ0V4TFV5Qk9aWGgwTVJzd0dRWURWUVFECkV4Sk1TMU1nVG1WNGRDQlNiMjkwSUVOQklETXdJQmNOTWpJd01USXdNVEV3TWpJMVdoZ1BNakExTWpBeE1UTXgKTVRBeU5UVmFNSE14Q3pBSkJnTlZCQVlUQWtWVE1SRXdEd1lEVlFRSUV3aEhhWEIxZW10dllURVJNQThHQTFVRQpCeE1JUVhKeVlYTmhkR1V4SVRBT0JnTlZCQW9UQjFNdUlFTnZiM0F3RHdZRFZRUUtFd2hNUzFNZ1RtVjRkREViCk1Ca0dBMVVFQXhNU1RFdFRJRTVsZUhRZ1VtOXZkQ0JEUVNBek1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMEQKQVFjRFFnQUU1aTFxZnlZU2xLaWt3SDhGZkhvQWxVWE44RlE3aE1OMERaTk8vVzdiSE44NVFpZ09ZeVQ1bWNYMgpXbDJtSTVEL0xQT1BKd0l4N1ZZcmxZU1BMTm5ndjZOak1HRXdEZ1lEVlIwUEFRSC9CQVFEQWdFR01BOEdBMVVkCkV3RUIvd1FGTUFNQkFmOHdIUVlEVlIwT0JCWUVGUGRURSs3a0k2MXFXSHFtUktZai9OaElIS01lTUI4R0ExVWQKSXdRWU1CYUFGUGRURSs3a0k2MXFXSHFtUktZai9OaElIS01lTUFvR0NDcUdTTTQ5QkFNQ0EwY0FNRVFDSUI2QQptZStjRzQ0MjBpNE5QZ1ZwWVRHN3hFN2lvbG0xOXhqRC9PcS9TeWt0QWlBaWRBK2JTanpvVHZxckRieDBqaHBiCmJpTnFycHZJY255TEY1MXQ5cHdBL1E9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0t",
			PublicKeyBase64:  "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFNWkxcWZ5WVNsS2lrd0g4RmZIb0FsVVhOOEZRNwpoTU4wRFpOTy9XN2JITjg1UWlnT1l5VDVtY1gyV2wybUk1RC9MUE9QSndJeDdWWXJsWVNQTE5uZ3Z3PT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==",
		}

		cert := secrets.Cert{
			Status:       "issued",
			SerialNumber: serialNumber,
			Name:         caName,
			KeyMetadata:  keyMetadata,
			Subject:      subject,
			CertContent:  certContent,
			CaTTL:        2000,
			EnrollerTTL:  1000,
			ValidFrom:    "2022-01-31 15:00:08 +0000 UTC",
			ValidTo:      "2022-04-18 23:00:37 +0000 UTC",
		}
		return cert*/
}

/*func NewVaultSecretsMock(t *testing.T) (*vaultApi.Client, error) {
	t.Helper()

	coreConfig := &vault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"pki": pki.Factory,
		},
	}

	core, keyShares, rootToken := vault.TestCoreUnsealedWithConfig(t, coreConfig)
	_ = keyShares

	_, addr := httpa.TestServer(t, core)

	conf := vaultApi.DefaultConfig()
	conf.Address = strings.ReplaceAll(conf.Address, "https://127.0.0.1:8200", addr)

	client, err := vaultApi.NewClient(conf)
	if err != nil {
		return nil, err
	}
	client.SetToken(rootToken)

	//Mount CA PKI Backend
	_, err = client.Logical().Write("sys/mounts/Lamassu-Root-CA1-RSA4096", map[string]interface{}{
		"type": "pki",
		"config": map[string]interface{}{
			"max_lease_ttl": "262800h",
		},
	})
	if err != nil {
		return nil, err
	}

	//Setup CA Role
	_, err = client.Logical().Write("Lamassu-Root-CA1-RSA4096/roles/enroller", map[string]interface{}{
		"allow_any_name": true,
		"max_ttl":        "262800h",
		"key_type":       "any",
	})
	if err != nil {
		return nil, err
	}

	//Setup CA internal root certificate
	_, err = client.Logical().Write("Lamassu-Root-CA1-RSA4096/root/generate/internal", map[string]interface{}{
		"common_name":  "LKS Next Root CA 1",
		"key_type":     "rsa",
		"key_bits":     "4096",
		"organization": "LKS Next S. Coop",
		"country":      "ES",
		"ttl":          "262800h",
		"province":     "Gipuzkoa",
		"locality":     "Arrasate",
	})
	if err != nil {
		return nil, err
	}

	return client, err
}*/

func testGetDeviceCert() dto.DeviceCert {
	subject := dto.Subject{
		C:  "ES",
		ST: "Gipuzkoa",
		L:  "Locality",
		O:  "Organization",
		OU: "OrganizationalUnit",
		CN: "testDeviceMock",
	}
	log := dto.DeviceCert{
		DeviceId:     "1",
		SerialNumber: "0b-f5-eb-c2-7d-6a-6b-d8-67-04-ae-ae-d9-58-13-f4",
		CAName:       "",
		Status:       "",
		CRT:          "",
		Subject:      dto.Subject(subject),
		ValidFrom:    "",
		ValidTo:      "",
	}
	return log
}

func testCert(s string) *x509.CertificateRequest {

	data, _ := base64.StdEncoding.DecodeString(s)
	block, _ := pem.Decode([]byte(data))
	csr, _ := x509.ParseCertificateRequest(block.Bytes)
	return csr
}

func testDevice(id string) dto.Device {
	keyMetadata := dto.PrivateKeyMetadataWithStregth{
		KeyType:     "rsa",
		KeyBits:     4096,
		KeyStrength: "",
	}

	subject := dto.Subject{
		C:  "ES",
		ST: "Gipuzkoa",
		L:  "Locality",
		O:  "Organization",
		OU: "OrganizationalUnit",
		CN: "testDeviceMock",
	}
	device := dto.Device{
		Id:                id,
		Alias:             "testDeviceMock",
		Status:            "DEVICE_PROVISIONED",
		DmsId:             "1",
		Subject:           dto.Subject(subject),
		KeyMetadata:       dto.PrivateKeyMetadataWithStregth(keyMetadata),
		CreationTimestamp: "2022-01-11T07:02:40.082286Z",
	}

	return device
}

func testDeviceNoSerialNumber() dto.Device {
	keyMetadata := dto.PrivateKeyMetadataWithStregth{
		KeyType:     "rsa",
		KeyBits:     4096,
		KeyStrength: "",
	}

	subject := dto.Subject{
		C:  "ES",
		ST: "Gipuzkoa",
		L:  "Locality",
		O:  "Organization",
		OU: "OrganizationalUnit",
		CN: "testDeviceMock",
	}
	device := dto.Device{
		Id:                "noSN",
		Alias:             "noSN",
		Status:            "CERT_REVOKED",
		DmsId:             "1",
		Subject:           dto.Subject(subject),
		KeyMetadata:       dto.PrivateKeyMetadataWithStregth(keyMetadata),
		CreationTimestamp: "2022-01-11T07:02:40.082286Z",
	}

	return device
}

func StringToCSR(s string) (*x509.CertificateRequest, error) {
	csr2Str := s
	data2, _ := base64.StdEncoding.DecodeString(csr2Str)
	block2, _ := pem.Decode([]byte(data2))
	c, err := x509.ParseCertificateRequest(block2.Bytes)
	//c.Raw = data2
	return c, err
}

func StringToCert(s string) (*x509.Certificate, error) {
	data, _ := base64.StdEncoding.DecodeString(s)
	block, _ := pem.Decode([]byte(data))
	c, err := x509.ParseCertificate(block.Bytes)

	return c, err
}
