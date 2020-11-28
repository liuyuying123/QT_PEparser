#include<stdio.h>
#include<stdlib.h>
#include<windows.h>
#include "peparser.h"
#include "ui_mainwindow.h"
#include "mainwindow.h"
#include<string.h>
#include<iostream>
using namespace std;


PEparser::PEparser(QWidget *parent):
QMainWindow(parent)
{
}

PEparser::~PEparser(){

}


void PEparser::slot_init(Ui::MainWindow* ui){
    ui->information_text->clear();
    ui->information_text->append("进行DOS头的解析\n");//将ui传递过来就可以直接使用
    if(!this->file_name){
        ui->information_text->append("还未打开文件，请先打开文件！\n");
        return;
    }

    //计算文件长度
    int len=0;
    len=this->length(this->fp);
    this->f_file_buffer=(void*)malloc(len);
    if(!this->f_file_buffer){
        ui->information_text->append("文件buffer初始化失败！\n");
        return;
    }
    memset(this->f_file_buffer,0,len);

    //将文件读入内存
    int i=0;
    if(fread(this->f_file_buffer,len,1,this->fp)==0){
        ui->information_text->append("将文件读入内存中失败！\n");
        return;
    }

    //开始初始化
    this->p_dos_header=(PIMAGE_DOS_HEADER)this->f_file_buffer;
    this->p_nt_header=(PIMAGE_NT_HEADERS)((int64_t)this->f_file_buffer+this->p_dos_header->e_lfanew);
    this->p_file_header=(PIMAGE_FILE_HEADER)((int64_t)this->p_nt_header+4);
    this->p_optional_header=(PIMAGE_OPTIONAL_HEADER)((int64_t)this->p_file_header+IMAGE_SIZEOF_FILE_HEADER);
    this->p_section_header=(PIMAGE_SECTION_HEADER)((int64_t)this->p_optional_header+this->p_file_header->SizeOfOptionalHeader);
    ui->information_text->append("初始化PE头成功!\n");

}


//开始解析DOS头和NT头
void PEparser::slot_dos_nt(Ui::MainWindow* ui){
    ui->information_text->clear();//现将information_text中的内容清除
    if(*(PWORD)this->p_dos_header!= IMAGE_DOS_SIGNATURE){
        ui->information_text->append("不是有效的MZ标志！\n");
        return;
    }
    else{
        ui->information_text->append("------------DOS头的信息如下-------------\n");
        ui->information_text->append("MZ标志："+QString::number(this->p_dos_header->e_magic,16));
        ui->information_text->append("PE偏移："+QString::number(this->p_dos_header->e_lfanew,16));
    }


    if (*((PDWORD)((int64_t)this->p_nt_header)) != IMAGE_NT_SIGNATURE){
        ui->information_text->append("不是有效的PE标志！\n"+QString::number(*((PDWORD)((int64_t)(this->p_nt_header))),16));
       // return;
    }else{
        ui->information_text->append("------------NT头信息如下----------------");
        ui->information_text->append("NT: "+QString::number(this->p_nt_header->Signature,16));
    }


    //打印标准PE头信息如下
    ui->information_text->append("------------标准PE头信息如下-------------");
    ui->information_text->append("PE_MACHINE: "+QString::number(this->p_file_header->Machine,16));
    ui->information_text->append("节的数量: "+QString::number(this->p_file_header->NumberOfSections,16));
    ui->information_text->append("SizeOfOptionalHeader(可选PE头大小): "+QString::number(this->p_file_header->SizeOfOptionalHeader,16));

    //打印可选PE头信息
    ui->information_text->append("------------可选PE头信息如下------------");
    ui->information_text->append("Magic: "+QString::number(this->p_optional_header->Magic,16));
    ui->information_text->append("AddressOfEntryPoint: "+QString::number(this->p_optional_header->AddressOfEntryPoint,16));
    ui->information_text->append("ImageBase: "+QString::number(this->p_optional_header->ImageBase,16));
    ui->information_text->append("SizeOfHeaders: "+QString::number(this->p_optional_header->SizeOfHeaders,16));
    ui->information_text->append("SectionAlignment: "+QString::number(this->p_optional_header->SectionAlignment,16));
    ui->information_text->append("FileAlignment: "+QString::number(this->p_optional_header->FileAlignment,16));

}




//开始解析节的信息
void PEparser::slot_section(Ui::MainWindow* ui){
    ui->information_text->clear();
    ui->information_text->append("---------节表信息如下---------");
    PIMAGE_SECTION_HEADER tempSection=this->p_section_header;
    int numsofsections=this->p_file_header->NumberOfSections;
    for(int i=0;i<numsofsections;i++,tempSection++){
        ui->information_text->append("---------第"+QString::number(i)+"个节信息----------");
//        char* name=nullptr;
//        for(int j=0;j<IMAGE_SIZEOF_SHORT_NAME;j++){
//            name+=(char)(tempSection->Name[j]);
//        }
        //ui->information_text->append("Section_name: "+name);
        ui->information_text->append("Misc: "+QString::number(tempSection->Misc.VirtualSize,16));
        ui->information_text->append("VirtualAddress: "+QString::number(tempSection->VirtualAddress,16));
        ui->information_text->append("SizeOfRawData: "+QString::number(tempSection->SizeOfRawData,16));
        ui->information_text->append("PointerToRawData: "+QString::number(tempSection->PointerToRawData,16));
        ui->information_text->append("Characteristics: "+QString::number(tempSection->Characteristics,16));
    }

}







//开始解析导出表信息
void PEparser::slot_export(Ui::MainWindow* ui){
    ui->information_text->clear();
    ui->information_text->append("-----------开始解析导出表信息！------------");

    PIMAGE_EXPORT_DIRECTORY exportTable;
    //指向文件中的导出表位置，是相对地址
    DWORD64  exportTableFoa=(DWORD64)this->rva2foa(this->p_optional_header->DataDirectory[0].VirtualAddress);

    //得到文件中的导出表导出表位置并且转换成导出表结构
    //从这里开始就有问题了
//    exportTable=(PIMAGE_EXPORT_DIRECTORY)(exportTableFoa+this->f_file_buffer);

//    //得到名称表在文件中的具体位置，是相对地址
//    DWORD  AddressOfNametableFoa=this->rva2foa((DWORD)(exportTable->AddressOfNames));
//    //得到名称表在文件buffer中的绝对位置
//    PDWORD64 addressofnames=(PDWORD64)((DWORD64)(this->f_file_buffer)+(DWORD64)AddressOfNametableFoa);
//    PDWORD64 tempaddressofnames= addressofnames;

//    //打印AddressOfNames表中所有地址指向的函数名称
//    for(DWORD i=0;i<=exportTable->NumberOfFunctions;i++){
//        DWORD64 functionnameaddr=(DWORD64)(*(addressofnames));//指向第i个函数名称的地址
//        addressofnames+=4;
////        char* functionName=(char*)((DWORD64)this->f_file_buffer+(DWORD64)(this->rva2foa(functionnameaddr)));
////        QString str="Name: ";
////        ui->information_text->append(functionName);
//    }
//    ui->information_text->append("this");


//    //函数地址表
//    PDWORD64 addressOfFunctionTable=(PDWORD64)((DWORD64)this->f_file_buffer+this->rva2foa((DWORD64)exportTable->AddressOfFunctions));
//    for(DWORD i=0;i<exportTable->NumberOfFunctions;i++){
//        ui->information_text->append("addr: "+QString::number(*(addressOfFunctionTable+i),16));
//    }

//    //AdressOfNameOridals序号表
//    PDWORD64 addressOfNameOridals=(PDWORD64)((DWORD64)this->f_file_buffer+this->rva2foa((DWORD64)exportTable->AddressOfNameOrdinals));
//    for(DWORD i=0;i<exportTable->NumberOfNames;i++){
//        ui->information_text->append("odr: "+QString::number(*(addressOfNameOridals+i),16));
//    }

//    //打印函数地址表中的所有函数信息，如果有名字的话找到名字并打印，如果没有名字的话就只打印地址和序号
//    ui->information_text->append("Base    Odr    VAddress    Name");
//    for(DWORD i=0;i<exportTable->NumberOfFunctions;i++){
//        DWORD addOfFunc=*(addressOfFunctionTable+i);//得到函数地址表中函数的地址
//        if (addOfFunc==0x0){
//            //0地址函数跳过，导出序号间隔不是1
//            continue;
//        }

//        //在导出序号表中寻找序号
//        int odrOfFuncIndex=-1;
//        for(DWORD j=0;j<exportTable->NumberOfNames;j++){
//            WORD odrOfFunc=*(addressOfNameOridals+j);
//            if(i==odrOfFunc){
//                //有导出函数名
//                odrOfFuncIndex=j;
//                break;
//            }
//        }

//        if(odrOfFuncIndex>=0){
//            //有导出函数名
//            DWORD  functionNameAddr=*(addressofnames+odrOfFuncIndex);
//            //记得rva2foa的返回值看弄不弄成64位，还是直接强制将32位转换成64位即可
//            char* functionName=(char*)((DWORD64)this->f_file_buffer+this->rva2foa(functionNameAddr));
//            qDebug("出错了");
//            ui->information_text->append(QString::number(exportTable->Base,16)+QString::number(i)+QString::number(addOfFunc,16)+functionName);
//        }
//        else{
//            //没有导出函数名
//            ui->information_text->append(QString::number(exportTable->Base,16)+QString::number(i)+QString::number(addOfFunc,16)+"-");
//        }
//    }
}




//初始化所有的头部和文件buffer
char* PEparser::init_file_buffer(char* filename) {
    char* show_info=NULL;
    this->file_name=filename;
    FILE* fp=NULL;
    fopen_s(&fp,this->file_name,"rb");
    if(!fp){
        show_info="打开文件失败！\n";
        return show_info;
}
    else{
        this->fp=fp;//将文件指针保留下来
        show_info="打开文件成功！\n";
    }

    return show_info;
}



//计算文件长度
int PEparser::length(FILE* fp) {
           //定义文件大小
           int num;
           //将文件指针移到文件尾
           fseek(fp, 0, SEEK_END);
           num = ftell(fp);//得到当前文件指针对文件头的偏移
           fseek(fp, 0, SEEK_SET);
           return num;
}



//rva转换成foa
DWORD PEparser::rva2foa(DWORD rva) {
    if(rva<=this->p_optional_header->SizeOfHeaders){
            return rva;
        }

    //节表数量
    int sectionnumber = this->p_file_header->NumberOfSections;
    //偏移
    DWORD pianyi = rva;
    //rva落在哪个节里面
    PIMAGE_SECTION_HEADER temp2sectionheader = this->p_section_header;
    for (DWORD i = 0; i < sectionnumber; i++,temp2sectionheader++) {
        if ((pianyi >= temp2sectionheader->VirtualAddress) && (pianyi <= temp2sectionheader->VirtualAddress + temp2sectionheader->Misc.VirtualSize)) {
            return pianyi - temp2sectionheader->VirtualAddress + temp2sectionheader->PointerToRawData;
        }
    }
    return -1;
}
