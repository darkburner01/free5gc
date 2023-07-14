package service

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"github.com/sirupsen/logrus"

	haf_context "github.com/free5gc/haf/internal/context"
	"github.com/free5gc/haf/internal/logger"
	"github.com/free5gc/haf/internal/sbi/consumer"
	"github.com/free5gc/haf/internal/sbi/ueauthentication"
	"github.com/free5gc/haf/pkg/factory"
	"github.com/free5gc/util/httpwrapper"
	logger_util "github.com/free5gc/util/logger"
)

type HafApp struct {
	cfg     *factory.Config
	hafCtx *haf_context.HAFContext
}

func NewApp(cfg *factory.Config) (*HafApp, error) {
	haf := &HafApp{cfg: cfg}
	haf.SetLogEnable(cfg.GetLogEnable())
	haf.SetLogLevel(cfg.GetLogLevel())
	haf.SetReportCaller(cfg.GetLogReportCaller())

	haf_context.Init()
	haf.hafCtx = haf_context.GetSelf()
	return haf, nil
}

func (a *HafApp) SetLogEnable(enable bool) {
	logger.MainLog.Infof("Log enable is set to [%v]", enable)
	if enable && logger.Log.Out == os.Stderr {
		return
	} else if !enable && logger.Log.Out == ioutil.Discard {
		return
	}

	a.cfg.SetLogEnable(enable)
	if enable {
		logger.Log.SetOutput(os.Stderr)
	} else {
		logger.Log.SetOutput(ioutil.Discard)
	}
}

func (a *HafApp) SetLogLevel(level string) {
	lvl, err := logrus.ParseLevel(level)
	if err != nil {
		logger.MainLog.Warnf("Log level [%s] is invalid", level)
		return
	}

	logger.MainLog.Infof("Log level is set to [%s]", level)
	if lvl == logger.Log.GetLevel() {
		return
	}

	a.cfg.SetLogLevel(level)
	logger.Log.SetLevel(lvl)
}

func (a *HafApp) SetReportCaller(reportCaller bool) {
	logger.MainLog.Infof("Report Caller is set to [%v]", reportCaller)
	if reportCaller == logger.Log.ReportCaller {
		return
	}

	a.cfg.SetLogReportCaller(reportCaller)
	logger.Log.SetReportCaller(reportCaller)
}

func (a *HafApp) Start(tlsKeyLogPath string) {
	logger.InitLog.Infoln("Server started")

	router := logger_util.NewGinWithLogrus(logger.GinLog)
	ueauthentication.AddService(router)

	pemPath := factory.HafDefaultCertPemPath
	keyPath := factory.HafDefaultPrivateKeyPath
	sbi := factory.HafConfig.Configuration.Sbi
	if sbi.Tls != nil {
		pemPath = sbi.Tls.Pem
		keyPath = sbi.Tls.Key
	}

	self := a.hafCtx
	// Register to NRF
	profile, err := consumer.BuildNFInstance(self)
	if err != nil {
		logger.InitLog.Error("Build HAF Profile Error")
	}
	_, self.NfId, err = consumer.SendRegisterNFInstance(self.NrfUri, self.NfId, profile)
	if err != nil {
		logger.InitLog.Errorf("HAF register to NRF Error[%s]", err.Error())
	}

	addr := fmt.Sprintf("%s:%d", self.BindingIPv4, self.SBIPort)

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)
	go func() {
		defer func() {
			if p := recover(); p != nil {
				// Print stack for panic to log. Fatalf() will let program exit.
				logger.InitLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
			}
		}()

		<-signalChannel
		a.Terminate()
		os.Exit(0)
	}()

	server, err := httpwrapper.NewHttp2Server(addr, tlsKeyLogPath, router)
	if server == nil {
		logger.InitLog.Errorf("Initialize HTTP server failed: %+v", err)
		return
	}

	if err != nil {
		logger.InitLog.Warnf("Initialize HTTP server: +%v", err)
	}

	serverScheme := factory.HafConfig.Configuration.Sbi.Scheme
	if serverScheme == "http" {
		err = server.ListenAndServe()
	} else if serverScheme == "https" {
		err = server.ListenAndServeTLS(pemPath, keyPath)
	}

	if err != nil {
		logger.InitLog.Fatalf("HTTP server setup failed: %+v", err)
	}
}

func (a *HafApp) Terminate() {
	logger.InitLog.Infof("Terminating HAF...")
	// deregister with NRF
	problemDetails, err := consumer.SendDeregisterNFInstance()
	if problemDetails != nil {
		logger.InitLog.Errorf("Deregister NF instance Failed Problem[%+v]", problemDetails)
	} else if err != nil {
		logger.InitLog.Errorf("Deregister NF instance Error[%+v]", err)
	} else {
		logger.InitLog.Infof("Deregister from NRF successfully")
	}

	logger.InitLog.Infof("HAF terminated")
}
