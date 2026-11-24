#!/usr/bin/env python3
"""Execute production ARM entry in Unicorn; callback is an explicit ABI adapter.
run.py separately executes the real callback. This test covers register/flags/replay only.
"""
from pathlib import Path
import argparse,tempfile,subprocess,struct
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn import arm64_const as r
p=argparse.ArgumentParser();p.add_argument('--output',type=Path);a=p.parse_args()
root=Path(__file__).resolve().parents[2]
s=(root/'app/src/main/cpp/targets/home/home_layout_dart_arm64.S').read_text()
mac=s[s.index('.macro dart_save'):s.index('/* No relocated Dart BL')]
entry=s[s.index('.globl hc_folder_mike_entry'):s.index('/* Paired getter:')]
data='\n.data\n.p2align 3\n'
for name,value in [('ready',1),('width_field',15),('height_slot',-56),('height_field',23),('continue',0x700000),('original',0x710000)]:
 data+=f'.globl hc_folder_mike_{name}\nhc_folder_mike_{name}: .quad {value}\n'
assembly='.text\n'+mac+entry+'\n.globl hc_folder_mike_body\nhc_folder_mike_body: ret\n'+data

def run(out):
 out.mkdir(parents=True,exist_ok=True);(out/'stub.S').write_text(assembly)
 subprocess.run(['aarch64-linux-gnu-as',str(out/'stub.S'),'-o',str(out/'stub.o')],check=True)
 subprocess.run(['aarch64-linux-gnu-ld','-Ttext=0x100000','-Tdata=0x110000','-e','hc_folder_mike_entry',str(out/'stub.o'),'-o',str(out/'stub.elf')],check=True)
 syms={}
 for line in subprocess.check_output(['aarch64-linux-gnu-nm',str(out/'stub.elf')],text=True).splitlines():
  part=line.split()
  if len(part)==3:syms[part[2]]=int(part[0],16)
 # Read ELF sections using the repository's read-only reader.
 import sys
 sys.path.insert(0,str(root/'tests/home-layout-native'));from dart_dump import Elf
 e=Elf(out/'stub.elf')
 for ready in [0,1]:
  uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
  for base,length in [(0x100000,0x20000),(0x200000,0x10000),(0x300000,0x10000),(0x400000,0x10000),(0x500000,0x10000),(0x600000,0x10000),(0x700000,0x20000)]:uc.mem_map(base,length)
  for sec in ['.text','.data']:
   fields=e.sections[e.section_names[sec]];uc.mem_write(fields[3],e.data[fields[4]:fields[4]+fields[5]])
  uc.mem_write(syms['hc_folder_mike_ready'],struct.pack('<Q',ready))
  baseline={}
  for i in range(31):
   value=0x100+i;uc.reg_write(getattr(r,f'UC_ARM64_REG_X{i}'),value);baseline[i]=value
  baseline.update({0:0x500001,15:0x300800,27:0x600000,28:0x1234,29:0x400800,30:0xabcdef})
  for i,value in baseline.items():uc.reg_write(getattr(r,f'UC_ARM64_REG_X{i}'),value)
  qbefore={}
  for i in range(32):
   value=(0x1122334455667788+i)<<64|0x9988776655443322+i;uc.reg_write(getattr(r,f'UC_ARM64_REG_Q{i}'),value);qbefore[i]=value
  uc.reg_write(r.UC_ARM64_REG_SP,0x200800);uc.reg_write(r.UC_ARM64_REG_NZCV,0xa0000000)
  uc.mem_write(0x400800-56,struct.pack('<d',88.0));uc.mem_write(0x500010,b'\xaa'*16)
  calls=[]
  def code(uc,address,size,user):
   if address in [0x700000,0x710000]:uc.emu_stop();return
   if address==syms['hc_folder_mike_body']:
    calls.append(address)
    assert uc.reg_read(r.UC_ARM64_REG_X1)==0x400800
    assert uc.reg_read(r.UC_ARM64_REG_X2)==0x123400000000
    assert uc.reg_read(r.UC_ARM64_REG_X3)==0x600000
    saved=uc.reg_read(r.UC_ARM64_REG_X0)
    uc.mem_write(saved+160,struct.pack('<dQ',65.5,0))
    # AAPCS callee may trash caller-save GPR/SIMD and flags.
    for i in list(range(15))+[18]:uc.reg_write(getattr(r,f'UC_ARM64_REG_X{i}'),0xdeaddead)
    for i in range(32):uc.reg_write(getattr(r,f'UC_ARM64_REG_Q{i}'),0)
    uc.reg_write(r.UC_ARM64_REG_NZCV,0x50000000)
  uc.hook_add(UC_HOOK_CODE,code)
  uc.emu_start(syms['hc_folder_mike_entry'],0,count=2000)
  assert uc.reg_read(r.UC_ARM64_REG_PC)==(0x700000 if ready else 0x710000)
  assert len(calls)==ready
  assert uc.reg_read(r.UC_ARM64_REG_SP)==0x200800
  assert uc.reg_read(r.UC_ARM64_REG_NZCV)==0xa0000000
  for i,value in baseline.items():
   if i in [16,17]:continue # Dart scratch registers explicitly reserved
   assert uc.reg_read(getattr(r,f'UC_ARM64_REG_X{i}'))==value,(ready,i)
  for i,value in qbefore.items():
   actual=uc.reg_read(getattr(r,f'UC_ARM64_REG_Q{i}'))
   if i==0 and ready:assert actual==int.from_bytes(struct.pack('<d',88.0),'little')
   else:assert actual==value,(ready,'q',i)
  if ready:
   assert struct.unpack('<dd',uc.mem_read(0x500010,16))==(65.5,88.0)
  else:assert uc.mem_read(0x500010,16)==b'\xaa'*16
 print('PASS production ARM stub ready/off: GPR except Dart scratch, all SIMD except replay D0, NZCV, both SPs, callback ABI, width/height publications, original tail')
if a.output:run(a.output.resolve())
else:
 with tempfile.TemporaryDirectory(prefix='folder-mike-arm-') as tmp:run(Path(tmp))
