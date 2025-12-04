#include "stdafx.h"
#include "DriverWindow.h"
#include "../../MiscHelpers/Common/Settings.h"
#include "../API/Windows/ProcessHacker.h"
#include "../API/Windows/WindowsAPI.h"

CDriverWindow::CDriverWindow(QWidget *parent)
	: QMainWindow(parent)
{
	QWidget* centralWidget = new QWidget();
	ui.setupUi(centralWidget);
	this->setCentralWidget(centralWidget);
	this->setWindowTitle("Task Explorer - Driver Options");

	connect(ui.buttonBox, SIGNAL(accepted()), this, SLOT(accept()));
	connect(ui.buttonBox, SIGNAL(rejected()), this, SLOT(reject()));

	ui.chkUseDriver->setChecked(theConf->GetBool("OptionsKSI/KsiEnable", true));
	ui.deviceName->setText(theConf->GetString("OptionsKSI/DeviceName", "KTaskExplorer"));

	Refresh();

	if(((CWindowsAPI*)theAPI)->IsTestSigning())
		ui.signingPolicy->setText(tr("Test Signing Enabled"));
	else if(((CWindowsAPI*)theAPI)->IsCKSEnabled())
		ui.signingPolicy->setText(tr("Signature Required (CKS Enabled)"));
	else
		ui.signingPolicy->setText(tr("Signature Required"));
	
	restoreGeometry(theConf->GetBlob("DriverWindow/Window_Geometry"));

	m_TimerId = startTimer(250);
}

CDriverWindow::~CDriverWindow()
{
	theConf->SetBlob("DriverWindow/Window_Geometry", saveGeometry());

	if(m_TimerId != -1)
		killTimer(m_TimerId);
}

void CDriverWindow::closeEvent(QCloseEvent *e)
{
	this->deleteLater();
}

void CDriverWindow::accept()
{
	theConf->SetValue("OptionsKSI/KsiEnable", ui.chkUseDriver->isChecked());
	//theConf->SetValue("OptionsKSI/DeviceName", ui.deviceName->text());

	this->close();
}

void CDriverWindow::reject()
{
	this->close();
}

void CDriverWindow::timerEvent(QTimerEvent *e)
{
	if (e->timerId() != m_TimerId) 
	{
		QMainWindow::timerEvent(e);
		return;
	}

	Refresh();
}

void CDriverWindow::Refresh()
{
	if (CServicePtr pService = theAPI->GetService(ui.deviceName->text()))
	{
		ui.driverStatus->setText(pService->GetStateString());
		ui.driverStatus->setToolTip(pService->GetFileName());
	}
	else
	{
		ui.driverStatus->setText(tr("Not installed"));
		ui.driverStatus->setToolTip("");
	}

	if (KphCommsIsConnected())
	{
		ui.connection->setText(tr("Connected"));

		if(g_KsiDynDataLoaded)
			ui.dyn_data->setText(tr("DynData loaded"));
		else
			ui.dyn_data->setText(tr("DynData NOT loaded"));

		QString sLevel;
		KPH_LEVEL level = KphLevelEx(FALSE);
		switch (level)
		{
		case KphLevelNone: sLevel = tr("None"); break;
		case KphLevelMin: sLevel = tr("Minimal"); break;
		case KphLevelLow: sLevel = tr("Low"); break;
		case KphLevelMed: sLevel = tr("Medium"); break;
		case KphLevelHigh: sLevel = tr("High"); break;
		case KphLevelMax: sLevel = tr("Maximum"); break;
		}
		ui.verification->setText(sLevel);
	}
	else
	{
		ui.connection->setText(tr("Disconnected"));

		ui.dyn_data->setText(tr("N/A"));

		ui.verification->setText(tr("N/A"));
	}
}