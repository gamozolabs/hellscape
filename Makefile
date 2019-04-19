all: hellscape.exe

test: hellscape.exe
	hellscape.exe

hellscape.exe: objs/hellscape.obj
	link /nologo /debug /SUBSYSTEM:CONSOLE /OUT:hellscape.exe objs/hellscape.obj

objs/hellscape.obj: objs srcs/hellscape.asm
	nasm -g -f win32 -o objs/hellscape.obj srcs/hellscape.asm

objs:
	mkdir objs

clean:
	-rmdir /s /q objs 2>NUL
	-del hellscape.exe hellscape.pdb hellscape.ilk 2>NUL

