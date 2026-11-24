// Host scalar/contract checks; no Dart VM or device execution claim.
#include "targets/home/home_folder_mike_layout.h"
#include <cassert>
#include <fstream>
#include <iterator>
#include <limits>
#include <vector>
#include <iostream>
using namespace home_layout;
int main(int argc, char **argv) {
    assert(argc == 2);
    FolderMikeInputs v{100, 400, 90, 5, false, false};
    assert(mike_folder_cell_width(v,3,true)==100);
    assert(mike_folder_cell_width(v,4,false)==67.5);
    assert(mike_folder_cell_width(v,4,true)==89);
    v.count_cell_x=4;
    assert(mike_folder_cell_width(v,4,false)==65.5); // (3*90+2*8-3*8)/4
    assert(mike_folder_cell_width(v,4,true)==83);
    v.is_pad=true;
    assert(mike_folder_cell_width(v,4,false)==93); // min(400,400-28)/4
    assert(mike_folder_cell_width(v,4,true)==93);
    v.is_pad=false;v.is_jeejen=true;v.count_cell_x=5;
    assert(mike_folder_cell_width(v,4,false)==59.5); // gap32
    v.cell_width_px=200;
    assert(mike_folder_cell_width(v,4,false)==65); // min(3*((400-26)/3)+64,356)-96
    v.screen_width_px=10;
    assert(mike_folder_cell_width(v,4,true)==v.original_cell_width);
    v={100,400,90,5,false,false};
    v.screen_width_px=std::numeric_limits<double>::quiet_NaN();
    assert(mike_folder_cell_width(v,4,true)==100);
    // The non-full-width native unordered cap uses preferred, so a NaN screen
    // width does not by itself poison an otherwise valid preferred width.
    assert(mike_folder_cell_width(v,4,false)==67.5);
    std::ifstream input(argv[1],std::ios::binary);
    const std::vector<char> bytes((std::istreambuf_iterator<char>(input)),{});
    constexpr uint32_t va=0x1ac1c44;
    assert(bytes.size()>=va+217*4);
    std::vector<uint32_t> body;
    for(size_t i=0;i<217;++i){uint32_t w=0;for(unsigned j=0;j<4;++j)w|=uint32_t(uint8_t(bytes[va+i*4+j]))<<(j*8);body.push_back(w);}
    FolderMikeSite site;
    assert(folder_mike_site(body,va,site));
    assert(site.window==0x32c && site.continuation==0x1ac1f80);
    assert(site.config_slot==-0x18 && site.width_slot==-0x40 && site.height_slot==-0x38);
    assert(site.width_field==0xf && site.height_field==0x17);
    assert(site.pad_pool==0x26bc8 && site.jeejen_pool==0x140c0);
    assert(site.condition_field==7 && site.device_kind_field==0x17 && site.launcher_mode_field==0x2f);
    assert(site.screen_width_field==0xb && site.cell_width_field==0x2b && site.count_cell_x_field==0x1b);
    for(size_t i=0;i<body.size();++i){auto bad=body;bad[i]=0xd503201f;assert(!folder_mike_site(bad,va,site));}
    auto moved=body;moved[17]^=0x400;moved[18]^=0x400;
    assert(folder_mike_site(moved,va,site));
    assert(site.pad_pool!=0x26bc8);
    auto edge=body;edge[0]=0x14000000u | ((0x330/4)&0x3ffffffu);
    assert(!folder_mike_site(edge,va,site));
    assert(!folder_mike_site(std::span(body).first(216),va,site));
    assert(!folder_mike_site(body,UINT32_MAX-8,site));
    std::cout<<"PASS scalar branches, current ELF producer ABI, 217 instruction mutations, pool relocation, entry guard\n";
}
