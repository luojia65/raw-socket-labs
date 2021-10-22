use core::mem::{MaybeUninit, size_of};

fn main() {
    let fd = unsafe {
        libc::socket(libc::PF_PACKET, libc::SOCK_RAW, libc::ETH_P_ALL)
    };
    println!("Raw socket fd: {}", fd);
    let mut buf = vec![0; 65536];
    let mut saddr = MaybeUninit::<libc::sockaddr>::uninit();
    let mut saddr_len = size_of::<libc::sockaddr>() as u32;
    let buf_len = unsafe {
        libc::recvfrom(fd, buf.as_mut_ptr() as *mut _, buf.len(), 0, saddr.as_mut_ptr(), &mut saddr_len)
    };
    println!("buf len = {}", buf_len);
    /*
    unsigned char *buffer = (unsigned char *) malloc(65536); //to receive data
    memset(buffer,0,65536);
    struct sockaddr saddr;
    int saddr_len = sizeof (saddr);
    
    //Receive a network packet and copy in to buffer
    buflen=recvfrom(sock_r,buffer,65536,0,&saddr,(socklen_t *)&saddr_len);
    if(buflen<0)
    {
    printf(error in reading recvfrom function\n);
    return -1;
    } */
    unsafe {
        libc::close(fd);
    }
}
