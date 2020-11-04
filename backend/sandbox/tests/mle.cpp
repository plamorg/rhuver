int main() {
	volatile void *ptr = ::operator new(1024*1024*1024); /* allocate 1GB memory */
	for(int i = 0; i < 1024; i++){
		*((char *)ptr + i) = i;
	}
}
