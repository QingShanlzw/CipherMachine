
// MFCApplication2Dlg.h: 头文件
//

#pragma once
#ifndef _AES_CBC256_H_
#   include "AES_CBC256.h"
#endif

// CMFCApplication2Dlg 对话框
class CMFCApplication2Dlg : public CDialogEx
{
// 构造
public:
	CMFCApplication2Dlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_MFCAPPLICATION2_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedButton1();

	
	afx_msg void OnBnClickedButton2();
	afx_msg void OnEnChangeMfceditbrowse1();

	//CString str1;
	CString FilePath;
	//aes加密后的密文
	//unsigned char* AESCBCEncrypt;
	int aesLen;
	int aesLen1;
	AES_CBC256 m_pcAES_CBC256;

	CString idc1;
	CString idc2;
	afx_msg void OnBnClickedButton3();
	afx_msg void OnBnClickedButton4();
};
