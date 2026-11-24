#!/usr/bin/env python3
"""Actual producer binder/callback extraction, real ELF body, host scalar checks.
No Android injection, Dart GC or ARM assembly execution is claimed.
"""
from pathlib import Path
import argparse,struct,subprocess,tempfile
p=argparse.ArgumentParser();p.add_argument('--elf',type=Path,required=True);p.add_argument('--mini',type=Path);p.add_argument('--output',type=Path);a=p.parse_args()
root=Path(__file__).resolve().parents[2]
source=(root/'app/src/main/cpp/targets/home/home_layout_hooks.cpp').read_text()
def function(signature):
 start=source.index(signature);op=source.index('{',start);depth=1;end=op+1
 while depth:
  depth+=(source[end]=='{')-(source[end]=='}');end+=1
 return source[start:end]
va=0x1ac1c44;size=0x364
if a.mini:
 import sys
 sys.path.insert(0,str(root/'tests/home-layout-native'))
 from dart_dump import Symbols
 va,size=Symbols(a.mini).by_name['FolderConfigHandler.handle']
b=a.elf.read_bytes();words=struct.unpack('<'+'I'*(size//4),b[va:va+size])
pre=r'''
#include "targets/home/home_folder_mike_layout.h"
#include <cstring>
#include <vector>
#include <array>
#include <cassert>
#include <iostream>
#include <cmath>
struct Source{};struct Slot{uintptr_t address=0;Source source;std::array<uint32_t,4>original_words{};void*replacement=nullptr;void**original=nullptr;};
struct Dart{uintptr_t load_base=0x100000000ULL;};Dart data,*g_dart=&data;
constexpr unsigned kFolderMikeSlot=0,kFolderMikeColumnsSlot=1;Slot g_slots[2];
uint64_t hc_folder_mike_config=0;void*hc_folder_mike_original=nullptr;void*hc_folder_mike_columns_original=nullptr;uintptr_t hc_folder_mike_continue=0;
int64_t hc_folder_mike_width_slot=0,hc_folder_mike_height_slot=0,hc_folder_mike_width_field=0,hc_folder_mike_height_field=0;
void hc_folder_mike_entry(){}
void hc_folder_mike_columns_entry(){}
constexpr int ANDROID_LOG_INFO=4;const char*kTag="test";int __android_log_print(int,const char*,const char*,...){return 0;}
home_layout::FolderMikeSite g_folder_mike_fields{};bool g_folder_mike_bound=false,g_folder_mike_startup_window=false;uint32_t g_folder_mike_owner=0,g_folder_mike_columns_site=0;
std::vector<uint32_t> image;
uint32_t imageva=VA,imageSize=SIZE;
namespace home_layout_engine{bool HomeLayoutEngineFindSymbol(const char*n,uint32_t*v,uint32_t*s){assert(std::strcmp(n,"FolderConfigHandler.handle")==0);*v=imageva;*s=imageSize;return true;}}
namespace dartscan{bool body(uint32_t v,std::vector<uint32_t>&out){if(v!=imageva)return false;out=image;return true;}}
bool bind_dart_target(uint32_t v,uintptr_t&out,Source&,std::array<uint32_t,4>&w){if(v==g_folder_mike_columns_site){out=data.load_base+v;w={0x91001800,0xaa1d03ef,0xa8c179fd,0xd65f03c0};return true;}if(v<imageva||(v-imageva)/4+4>image.size())return false;out=data.load_base+v;std::copy_n(image.begin()+(v-imageva)/4,4,w.begin());return true;}
'''.replace('VA',str(va)).replace('SIZE',str(size))
# std::copy_n needs algorithm independently of production include ordering.
pre='#include <algorithm>\n'+pre+'\n'+function('bool bind_folder_mike() {')+'\n'+function('extern "C" void hc_folder_mike_body(uintptr_t saved, uintptr_t frame, uintptr_t heap, uintptr_t pool) {')
pre+='\nint main(){image={'+','.join(hex(x) for x in words)+'};\n'
pre+=r'''
 hc_folder_mike_config=uint64_t(4)<<27;assert(!bind_folder_mike());
 assert(home_layout::folder_mike_site(image,imageva,g_folder_mike_fields));
 g_folder_mike_owner=imageva;g_folder_mike_columns_site=0x8e6ee8;g_folder_mike_startup_window=true;assert(bind_folder_mike());
 assert(g_slots[1].address==data.load_base+g_folder_mike_columns_site);
 assert(g_slots[0].original==&hc_folder_mike_original&&g_slots[1].original==&hc_folder_mike_columns_original);
 const auto f=g_folder_mike_fields;assert(hc_folder_mike_continue==data.load_base+imageva+f.window+16);
 assert(hc_folder_mike_width_slot==-64&&hc_folder_mike_height_slot==-56);
 assert(g_slots[0].address==data.load_base+imageva+f.window);
 alignas(16) static unsigned char arena[0x1000], pp[0x30000],framebuf[256],saved[704];
 const uintptr_t cfg=reinterpret_cast<uintptr_t>(arena)+1,key=reinterpret_cast<uintptr_t>(arena)+0x101;
 const uintptr_t fp=reinterpret_cast<uintptr_t>(framebuf)+128,pool=reinterpret_cast<uintptr_t>(pp);
 const uintptr_t heap=key&~uintptr_t(0xffffffffULL);assert(heap!=0);
 auto put=[](uintptr_t p,auto v){std::memcpy(reinterpret_cast<void*>(p),&v,sizeof(v));};
 auto dbl=[](uintptr_t p){double v;std::memcpy(&v,reinterpret_cast<void*>(p),8);return v;};
 put(fp+f.config_slot,uint64_t(cfg));put(fp+f.width_slot,100.0);put(fp+f.height_slot,88.0);
 put(cfg+f.condition_field,uint32_t(key));put(cfg+f.screen_width_field,400.0);put(cfg+f.cell_width_field,90.0);put(cfg+f.count_cell_x_field,int64_t(5));
 put(pool+f.pad_pool,uint32_t(0x12345671));put(pool+f.jeejen_pool,uint32_t(0x23456781));put(pool+0x40,uint32_t(0x34567891));
 put(key+f.device_kind_field,uint32_t(0));put(key+f.launcher_mode_field,uint32_t(0));
 auto call=[&](unsigned cols,bool full){hc_folder_mike_config=(uint64_t(cols)<<27)|(full?2:0);std::memset(saved,0xa5,sizeof saved);hc_folder_mike_body(reinterpret_cast<uintptr_t>(saved),fp,heap,pool);uint64_t high=1;std::memcpy(&high,saved+168,8);assert(high==0);for(unsigned i=0;i<sizeof saved;++i)if(i<160||i>=176)assert(saved[i]==0xa5);return dbl(reinterpret_cast<uintptr_t>(saved)+160);};
 unsigned char oldarena[sizeof arena],oldframe[sizeof framebuf];std::memcpy(oldarena,arena,sizeof arena);std::memcpy(oldframe,framebuf,sizeof framebuf);
 assert(call(3,true)==100);assert(call(4,false)==67.5);assert(call(4,true)==89);assert(call(7,true)==100);
 assert(std::memcmp(oldarena,arena,sizeof arena)==0);assert(std::memcmp(oldframe,framebuf,sizeof framebuf)==0);
 put(key+f.device_kind_field,uint32_t(0x12345671));assert(call(4,false)==93);
 put(key+f.device_kind_field,uint32_t(0));put(key+f.launcher_mode_field,uint32_t(0x23456781));assert(call(4,false)==59.5);
 put(cfg+f.count_cell_x_field,int64_t(4));assert(call(4,false)==65.5);
 put(cfg+f.condition_field,uint32_t(0x34567891));assert(call(4,true)==100);
 put(cfg+f.condition_field,uint32_t(key));put(cfg+f.screen_width_field,10.0);assert(call(4,true)==100);
 assert(dbl(fp+f.width_slot)==100&&dbl(fp+f.height_slot)==88);
 std::cout<<"PASS actual binder/callback: real ELF body, D0+upper64, untouched saves/locals/config, columns3/7, full/base, pad, jeejen, count4, sentinel, fallback\n";
}
'''
def run(out):
 out.mkdir(parents=True,exist_ok=True);cpp=out/'callback.cpp';cpp.write_text(pre)
 commands=[['g++','-std=c++20','-O2','-Wall','-Wextra','-Werror','-I',str(root/'app/src/main/cpp'),str(cpp),'-o',str(out/'callback')],[str(out/'callback')],['g++','-std=c++20','-O2','-Wall','-Wextra','-Werror','-I',str(root/'app/src/main/cpp'),str(Path(__file__).with_name('mike_layout_test.cpp')),'-o',str(out/'scalar')],[str(out/'scalar'),str(a.elf.resolve())]]
 for cmd in commands:subprocess.run(cmd,check=True)
if a.output:run(a.output.resolve())
else:
 with tempfile.TemporaryDirectory(prefix='folder-mike-layout-') as tmp:run(Path(tmp))
