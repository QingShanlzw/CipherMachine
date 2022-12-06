
// MFCApplication2Dlg.cpp: 实现文件
//
//#define FILE_BUFFER_LENGTH 300000
#include "pch.h"
#include "framework.h"
#include "MFCApplication2.h"
#include "MFCApplication2Dlg.h"
#include "afxdialogex.h"
#include <iostream>
#include <fstream>
#include <string> 
#include <iterator>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/md5.h>
#include <sstream>
#include <algorithm>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

#define RsaKeyLen 4096

using namespace std;
using std::stringstream;
char* Base64Encode(const char* input, int length, bool with_new_line);
char* Base64Decode(char* input, int length, bool with_new_line);
void createRsaKey();
void RsaPrivateEncrypt();
void  RsaPublicDecrypt();
int testMd5(CString s, CString s2);
RSA* rsa1;
string suffix;
string FileName;
// 用于应用程序“关于”菜单项的 CAboutDlg 对话框
class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CMFCApplication2Dlg 对话框



CMFCApplication2Dlg::CMFCApplication2Dlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_MFCAPPLICATION2_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CMFCApplication2Dlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);

	DDX_Text(pDX, IDC_EDIT1, idc1);
	DDX_Text(pDX, IDC_EDIT2, idc2);
	DDX_Text(pDX, IDC_MFCEDITBROWSE1, FilePath);
}

BEGIN_MESSAGE_MAP(CMFCApplication2Dlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &CMFCApplication2Dlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON2, &CMFCApplication2Dlg::OnBnClickedButton2)
	ON_EN_CHANGE(IDC_MFCEDITBROWSE1, &CMFCApplication2Dlg::OnEnChangeMfceditbrowse1)
	ON_BN_CLICKED(IDC_BUTTON3, &CMFCApplication2Dlg::OnBnClickedButton3)
	ON_BN_CLICKED(IDC_BUTTON4, &CMFCApplication2Dlg::OnBnClickedButton4)
END_MESSAGE_MAP()


// CMFCApplication2Dlg 消息处理程序

BOOL CMFCApplication2Dlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CMFCApplication2Dlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CMFCApplication2Dlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CMFCApplication2Dlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CMFCApplication2Dlg::OnBnClickedButton1()
{
	// TODO: 在此添加控件通知处理程序代码
	UpdateData(TRUE);
	RsaPublicDecrypt();

	ifstream ifs("./加密/ciphertext.lzw", ios::in | ios::binary);
	ifs.seekg(0, ifs.end);
	int len = ifs.tellg();
	ifs.seekg(0, ifs.beg);
	 char* decrypt_in_data = new  char[len];
	ifs.read(decrypt_in_data, len);
	ifs.close();
	//这里的len应该要写填充之后的，虽然最后解密出来是原文，但是在执行加密的时候，可能会暂时越界，一旦越界，delete的时候，就会有问题。
	unsigned char* decrypt_out_data = new unsigned char[len];
	
	bool decrypt_ret = m_pcAES_CBC256.AES_CBC256_Decrypt((unsigned char*)decrypt_in_data, decrypt_out_data, len);
	string s1;
	s1 = (char*)decrypt_out_data;
	ofstream location_out;
	location_out.open("./解密/target."+suffix, std::ios::out | std::ios::binary);  //以写入和在文件末尾添加的方式打开.txt文件，没有的话就创建该文件。
	location_out.write((char*)decrypt_out_data,aesLen1);
	location_out.close();
	delete[]decrypt_in_data;
	delete[]decrypt_out_data;
	UpdateData(FALSE);
}



void CMFCApplication2Dlg::OnBnClickedButton2()
{
	// TODO: 在此添加控件通知处理程序代码
	
	UpdateData(TRUE);
	int i,j;
	for ( i = FilePath.GetLength() - 1; i > 0 && FilePath[i] != '.'; i--)
		suffix += FilePath[i];
	reverse(suffix.begin(), suffix.end());
	CString s2 = "./加密/sign.txt";
	testMd5(FilePath,s2);
	RsaPrivateEncrypt();
	//createRsaKey();
	ifstream ifs;
	ifs.open(FilePath, ifstream::in | ios::binary);
	if (!ifs.fail()) {
		ifs.seekg(0, ifs.end);
		aesLen1 = ifs.tellg();
		ifs.seekg(0, ifs.beg);
		char* buffer = new char[aesLen1];
		ifs.read(buffer, aesLen1);
		ifs.close();
		aesLen = aesLen1;
		if (0 != aesLen1 % AES_BLOCK_SIZE) {
			aesLen = aesLen1 + (AES_BLOCK_SIZE - aesLen1 % AES_BLOCK_SIZE);
		}
		unsigned char* encrypt_out_data = new unsigned char[aesLen];//这里因为一开始写的是aeslen1，小了导致内存冲突
		bool encrypt_ret = m_pcAES_CBC256.AES_CBC256_Encrypt((unsigned char*)buffer, encrypt_out_data, aesLen1);

		
		ofstream location_out;
		
		location_out.open("./加密/ciphertext.lzw", ios::out|ios::binary );  //以写入和在文件末尾添加的方式打开.txt文件，没有的话就创建该文件。
		location_out.write((char*)encrypt_out_data, aesLen);
		location_out.close();
		delete[]buffer;
		delete[]encrypt_out_data;
		
	}

	UpdateData(FALSE);
}


void CMFCApplication2Dlg::OnEnChangeMfceditbrowse1()
{
	// TODO:  如果该控件是 RICHEDIT 控件，它将不
	// 发送此通知，除非重写 CDialogEx::OnInitDialog()
	// 函数并调用 CRichEditCtrl().SetEventMask()，
	// 同时将 ENM_CHANGE 标志“或”运算到掩码中。

	// TODO:  在此添加控件通知处理程序代码
	

}

//生成RSA公私钥

void createRsaKey() {
	size_t privateKeyLen = 0;
	size_t publicKeyLen = 0;

	char* privateKey = nullptr;
	char* publicKey = nullptr;

	RSA* KeyPair = RSA_generate_key(RsaKeyLen, RSA_3, NULL, NULL);

	BIO* pri = BIO_new(BIO_s_mem());
	BIO* pub = BIO_new(BIO_s_mem());

	PEM_write_bio_RSAPrivateKey(pri, KeyPair, NULL, NULL, 0, NULL, NULL);

	PEM_write_bio_RSA_PUBKEY(pub, KeyPair);

	// 获取公私钥长度  
	privateKeyLen = BIO_pending(pri);
	publicKeyLen = BIO_pending(pub);

	// 密钥对读取到字符串  
	privateKey = (char*)malloc(privateKeyLen + 1);
	publicKey = (char*)malloc(publicKeyLen + 1);

	BIO_read(pri, privateKey, privateKeyLen);
	BIO_read(pub, publicKey, publicKeyLen);

	privateKey[privateKeyLen] = '\0';
	publicKey[publicKeyLen] = '\0';

	ofstream pubof;
	pubof.open("publicKey.pem", std::ios::out |ios::binary);  //以写入和在文件末尾添加的方式打开.txt文件，没有的话就创建该文件。
	pubof.write(publicKey, publicKeyLen);
	pubof.close();

	ofstream priof;
	priof.open("privateKey.pem", std::ios::out);  //以写入和在文件末尾添加的方式打开.txt文件，没有的话就创建该文件。
	priof.write(privateKey, privateKeyLen );
	priof.close();
}

void RsaPrivateEncrypt() {
	//读取私钥
	ifstream ifs("privateKey.pem",ios::in|ios::binary);
	ifs.seekg(0, ifs.end);
	int len = ifs.tellg();
	ifs.seekg(0, ifs.beg);
	char* privateKey = new char[len];
	ifs.read(privateKey, len);
	ifs.close();

	BIO* keybio = BIO_new_mem_buf((unsigned char*)privateKey, -1);
	RSA* rsa = RSA_new();
	rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
	rsa1 = rsa;
	if (!rsa)
	{
		BIO_free_all(keybio);
		return;
	}
	//表示rsa可以处理数据的长度
	int maxnlen = RSA_size(rsa);
	char* text = new char[maxnlen + 1];
	memset(text, 0, maxnlen + 1);

	//获取要加密的明文
	ifstream ifs2("./加密/sign.txt", ios::in|ios::binary);
	ifs2.seekg(0, ifs2.end);
	int textlen = ifs2.tellg();
	ifs2.seekg(0, ifs2.beg);
	char* testText = new char[textlen];
	ifs2.read(testText, textlen);
	ifs2.close();

	int ret = RSA_private_encrypt(textlen, (const unsigned char*)testText, (unsigned char*)text, rsa, RSA_PKCS1_PADDING);
	//int ret = RSA_public_decrypt(textlen, (const unsigned char*)testText, (unsigned char*)text, rsa, RSA_PKCS1_PADDING);


	//私钥加密后写入
	ofstream ofs;
	ofs.open("./解密/sign.txt", std::ios::out |ios::binary);
	ofs.write((char*)text, ret);
	ofs.close();
	
	
	delete[]privateKey;
	delete[]text;
	delete[]testText;
}
void  RsaPublicDecrypt() {

	//读取公钥
	ifstream ifs("publicKey.pem", ios::in|ios::binary);
	ifs.seekg(0, ifs.end);
	int len = ifs.tellg();
	ifs.seekg(0, ifs.beg);
	char* publicKey = new char[len];
	ifs.read(publicKey, len);
	ifs.close();

	BIO* keybio = BIO_new_mem_buf((unsigned char*)publicKey, -1);
	RSA* rsa = RSA_new();
	rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
	int maxnLen = RSA_size(rsa);//256
	char* text = new char[maxnLen + 1];
	memset(text, 0, maxnLen + 1);

	//获取要解密的密文
	ifstream ifs2("./解密/sign.txt", ios::in|ios::binary);
	ifs2.seekg(0, ifs2.end);
	int textlen = ifs2.tellg();
	ifs2.seekg(0, ifs2.beg);
	char* testText = new char[textlen];
	ifs2.read(testText, textlen);
	ifs2.close();

	int ret = RSA_public_decrypt(textlen, (const unsigned char*)testText, (unsigned char*)text, rsa, RSA_PKCS1_PADDING);

	//公钥解密后写入
	ofstream ofs;
	ofs.open("./解密/sign.txt", std::ios::out | ios::binary);
	ofs.write((char*)text, ret);
	ofs.close();
	
	
	delete[]publicKey;
	delete[]text;
	delete[]testText;

}


//md5加密
int testMd5(CString s,CString s2)
{
	int ret = -1;
	int i = 0;
	unsigned char md[MD5_DIGEST_LENGTH];
	unsigned char buf[MD5_DIGEST_LENGTH * 2 + 1];

	MD5_CTX c;
	//获取要加密的明文
	ifstream ifs2(s, ios::in | ios::binary);
	ifs2.seekg(0, ifs2.end);
	int textlen = ifs2.tellg();
	ifs2.seekg(0, ifs2.beg);
	char* testText = new char[textlen];
	ifs2.read(testText, textlen);
	ifs2.close();


	//cout << "==============================" << endl;
	memset(md, 0, MD5_DIGEST_LENGTH);
	MD5((unsigned char*)testText, textlen, md);
	memset(buf, 0, MD5_DIGEST_LENGTH * 2 + 1);
	for (i = 0; i < MD5_DIGEST_LENGTH; i++)
	{
		sprintf((char*)&buf[i * 2], "%02X", md[i]);
	}
	ofstream ofs2;
	ofs2.open(s2, std::ios::out | ios::binary);
	ofs2.write((char*)buf, MD5_DIGEST_LENGTH * 2 + 1);
	ofs2.close();
	delete[]testText;
	return 0;
}

void CMFCApplication2Dlg::OnBnClickedButton3()
{
	// TODO: 在此添加控件通知处理程序代码
	UpdateData(TRUE);
	string t = ("./解密/target."+ suffix);
	CString s1 = t.c_str();
	CString s2 = "./解密/sign1.txt";
	testMd5(s1, s2);

	ifstream ifs("./解密/sign.txt", ios::in | ios::binary);
	ifs.seekg(0, ifs.end);
	int textlen1 = ifs.tellg();
	ifs.seekg(0, ifs.beg);
	char* sign1 = new char[textlen1];
	ifs.read(sign1, textlen1);
	ifs.close();

	ifstream ifs2(s2, ios::in | ios::binary);
	ifs2.seekg(0, ifs2.end);
	int textlen = ifs2.tellg();
	ifs2.seekg(0, ifs2.beg);
	char* sign = new char[textlen];
	ifs2.read(sign, textlen);
	ifs2.close();

	if (!strcmp(sign1, sign))
		idc1 = "认证成功";
	else idc1 = "认证失败";
	delete[]sign1;
	delete[]sign;
	UpdateData(FALSE);
}


void CMFCApplication2Dlg::OnBnClickedButton4()
{
	// TODO: 在此添加控件通知处理程序代码
	UpdateData(TRUE);
	string t = idc2;
	string tiv = t;
	reverse(tiv.begin(), tiv.end());
	char* s = new char[t.length()];
	char* siv = new char[tiv.length()];
	strcpy(s, t.c_str());
	unsigned char md[MD5_DIGEST_LENGTH];
	unsigned char mdiv[MD5_DIGEST_LENGTH];
	unsigned char buf[MD5_DIGEST_LENGTH * 2 + 1];
	unsigned char bufiv[MD5_DIGEST_LENGTH * 2 + 1];
	MD5((unsigned char*)s, t.length(), md);
	MD5((unsigned char*)siv, t.length(), mdiv);
	for (int i = 0; i < MD5_DIGEST_LENGTH; i++)
	{
		sprintf((char*)&buf[i * 2], "%02X", md[i]);
	}
	for (int i = 0; i < MD5_DIGEST_LENGTH; i++)
	{
		sprintf((char*)&bufiv[i * 2], "%02X", mdiv[i]);
	}

	memcpy(m_pcAES_CBC256.m_userKey, buf, USER_KEY_LENGTH);
	memcpy(m_pcAES_CBC256.m_ivec, bufiv, IVEC_LENGTH);

	int x = 5;
	UpdateData(FALSE);
}
