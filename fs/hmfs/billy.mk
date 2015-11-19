PRINTPATH := /home/billy/printtty
KBUILD_EXTRA_SYMBOLS := $(PRINTPATH)/Module.symvers

ins_print:
	sudo insmod $(PRINTPATH)/printt.ko
rm_print:
	sudo rmmod printt
ins_hmfs:
	sudo insmod ./hmfs.ko 
rm_hmfs:
	sudo rmmod hmfs
mount_hmfs:
	sudo mount -t hmfs -o physaddr=0x70000000,init=40M none ~/hmfsMount/
hmfs:
	sudo insmod ./hmfs.ko && sudo mount -t hmfs -o physaddr=0x70000000,init=40M none ~/hmfsMount/
nohmfs:
	sudo umount ~/hmfsMount && sudo rmmod hmfs

reset:
	make nohmfs && make hmfs
