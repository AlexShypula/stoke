  .text
  .globl wmemchr
  .type wmemchr, @function

#! file-offset 0x1841a0
#! rip-offset  0x1441a0
#! capacity    192 bytes

# Text                      #  Line  RIP       Bytes  Opcode              
.wmemchr:                   #        0x1441a0  0      OPC=<label>         
  xorl %ecx, %ecx           #  1     0x1441a0  2      OPC=xorl_r32_r32    
  nop                       #  2     0x1441a2  1      OPC=nop             
  testl %edx, %edx          #  3     0x1441a3  2      OPC=testl_r32_r32   
  je .L_144200              #  4     0x1441a5  2      OPC=je_label        
  nop                       #  5     0x1441a7  1      OPC=nop             
  nop                       #  6     0x1441a8  1      OPC=nop             
  nop                       #  7     0x1441a9  1      OPC=nop             
  nop                       #  8     0x1441aa  1      OPC=nop             
  nop                       #  9     0x1441ab  1      OPC=nop             
  nop                       #  10    0x1441ac  1      OPC=nop             
  nop                       #  11    0x1441ad  1      OPC=nop             
  movl %edi, %eax           #  12    0x1441ae  2      OPC=movl_r32_r32_1  
  cmpl %esi, (%r15,%rax,1)  #  13    0x1441b0  4      OPC=cmpl_m32_r32    
  jne .L_1441e0             #  14    0x1441b4  2      OPC=jne_label       
  nop                       #  15    0x1441b6  1      OPC=nop             
  nop                       #  16    0x1441b7  1      OPC=nop             
  nop                       #  17    0x1441b8  1      OPC=nop             
  nop                       #  18    0x1441b9  1      OPC=nop             
  nop                       #  19    0x1441ba  1      OPC=nop             
  nop                       #  20    0x1441bb  1      OPC=nop             
  nop                       #  21    0x1441bc  1      OPC=nop             
  nop                       #  22    0x1441bd  1      OPC=nop             
  nop                       #  23    0x1441be  1      OPC=nop             
  nop                       #  24    0x1441bf  1      OPC=nop             
  jmpq .L_144240            #  25    0x1441c0  5      OPC=jmpq_label_1    
  nop                       #  26    0x1441c5  1      OPC=nop             
  nop                       #  27    0x1441c6  1      OPC=nop             
  nop                       #  28    0x1441c7  1      OPC=nop             
.L_1441c0:                  #        0x1441c8  0      OPC=<label>         
  addl $0x4, %eax           #  29    0x1441c8  5      OPC=addl_eax_imm32  
  cmpl %esi, (%r15,%rax,1)  #  30    0x1441cd  4      OPC=cmpl_m32_r32    
  je .L_144220              #  31    0x1441d1  2      OPC=je_label        
.L_1441e0:                  #        0x1441d3  0      OPC=<label>         
  addl $0x1, %ecx           #  32    0x1441d3  3      OPC=addl_r32_imm8   
  cmpl %ecx, %edx           #  33    0x1441d6  2      OPC=cmpl_r32_r32    
  ja .L_1441c0              #  34    0x1441d8  2      OPC=ja_label        
.L_144200:                  #        0x1441da  0      OPC=<label>         
  nop                       #  35    0x1441da  1      OPC=nop             
  nop                       #  36    0x1441db  1      OPC=nop             
  nop                       #  37    0x1441dc  1      OPC=nop             
  xorl %eax, %eax           #  38    0x1441dd  2      OPC=xorl_r32_r32    
.L_144220:                  #        0x1441df  0      OPC=<label>         
  nop                       #  39    0x1441df  1      OPC=nop             
  nop                       #  40    0x1441e0  1      OPC=nop             
  nop                       #  41    0x1441e1  1      OPC=nop             
  nop                       #  42    0x1441e2  1      OPC=nop             
  nop                       #  43    0x1441e3  1      OPC=nop             
.L_144240:                  #        0x1441e4  0      OPC=<label>         
  retq                      #  44    0x1441e4  1      OPC=retq            
                                                                          
.size wmemchr, .-wmemchr
