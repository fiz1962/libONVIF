#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "OnvifDevice.h"
#include "OnvifDiscoveryClient.h"
#include "SoapHelper.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}


void MainWindow::on_pushButton_clicked()
{
    auto device = new OnvifDevice(QUrl("http://192.168.1.100:80/onvif/device_service"), this);
    device->SetAuth("admin", "passwd");
    device->Initialize();

    std::vector<tt__Profile> tokens = device->GetProfiles();

    for(int n=0; n<tokens.size(); n++)
        ui->textEdit->append("Profile ["+QString::number(n)+"]: Name "+tokens[n].Name+": Token ["+tokens[n].token+"]");

    ui->textEdit->append("");
}

void MainWindow::on_pushButton_2_clicked()
{
    auto device = new OnvifDevice(QUrl("http://192.168.1.100:80/onvif/device_service"), this);
    device->SetAuth("admin", "passwd");
    device->Initialize();

    std::vector<tt__Profile> tokens = device->GetProfiles();

    for(unsigned int n=0; n<tokens.size();n++)
        ui->textEdit->append("Profile(" +QString::number(n) + ") token = " + tokens[n].Name + " StreamUri = [" + device->GetStreamUri(tokens[n].token));
     ui->textEdit->append("");
}

void MainWindow::on_pushButton_3_clicked()
{
        auto ctxBuilder = SoapCtx::Builder();
        double discoverTime = 5000;

        ctxBuilder.SetSendTimeout(1000);
        ctxBuilder.SetReceiveTimeout(1000);
        auto discovery = new OnvifDiscoveryClient(QUrl("soap.udp://239.255.255.250:3702"), ctxBuilder.Build(), this);
        ProbeTypeRequest request;
        request.Types = "tds:Device";
        auto uuidOne = QString("uuid:%1").arg(SoapHelper::GenerateUuid());
        auto probeResponseTwo = discovery->Probe(request, uuidOne);
        request.Types = "tdn:NetworkVideoTransmitter";
        auto uuidTwo = QString("uuid:%1").arg(SoapHelper::GenerateUuid());
        auto probeResponseOne = discovery->Probe(request, uuidTwo);
        if(probeResponseOne && probeResponseTwo) {
            qDebug() << "Searching ONVIF devices for" << discoverTime / 1000 << "seconds";
            auto foundMatches = 0;
            auto beginTs = QDateTime::currentMSecsSinceEpoch();
            while(QDateTime::currentMSecsSinceEpoch() < beginTs + discoverTime) {
                auto matchResp = discovery->ReceiveProbeMatches();
                if(matchResp && matchResp.GetResultObject()) {
                    auto relatesTo = matchResp.GetSoapHeaderRelatesTo();
                    if(!relatesTo.isNull() && (uuidOne.compare(relatesTo) == 0 || uuidTwo.compare(relatesTo) == 0)) {
                        if(auto matchs = matchResp.GetResultObject()) {
                            if(matchs->wsdd__ProbeMatches) {
                                for(auto i = 0; i < matchs->wsdd__ProbeMatches->__sizeProbeMatch; ++i) {
                                    wsdd__ProbeMatchesType match = matchs->wsdd__ProbeMatches[i];
                                    for(auto ii = 0; ii < match.__sizeProbeMatch; ++ii) {
                                        foundMatches++;
                                        auto probe = match.ProbeMatch[ii];
                                        ui->textEdit->append("Found match:");
                                        ui->textEdit->append("    Type:" + QString(probe.Types));
                                        ui->textEdit->append("    Endpoint:" + QString(probe.XAddrs));
                                        ui->textEdit->append("");
                                        if(probe.wsa5__EndpointReference.Address) {
                                            ui->textEdit->append("     Reference:" + QString(probe.wsa5__EndpointReference.Address));
                                        }
                                        if(probe.Scopes) {
                                            auto scopeList = QString::fromLocal8Bit(probe.Scopes->__item).split(' ');
                                            auto matchBy = QString::fromLocal8Bit(probe.Scopes->MatchBy);
                                            if(!matchBy.isEmpty()) {
                                                qDebug() << "    Match:" << matchBy;
                                            }
                                            qDebug() << "    Scope:";
                                            for(auto scope : scopeList) {
                                                if(!scope.isEmpty()) qDebug() << "        " << scope;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
}
