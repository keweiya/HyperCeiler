#include "targets/home/tweaks/ht_plan.h"
#include "targets/home/tweaks/symtab.h"
#include "nativehook/elf_image.h"
#include <algorithm>
#include <cassert>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sys/stat.h>
// Host test never persists caches or accesses Android app data.
namespace home_layout_engine {
uint64_t ImageIdentity(const Image&) { return 1; }
bool LoadSymbolCache(uint64_t, std::vector<uint8_t>*) { return false; }
bool SaveSymbolCache(uint64_t, const std::vector<uint8_t>&) { return true; }
}
using namespace home_layout_engine;
int main(int argc,char**argv){
 assert(argc==2); std::ifstream f(argv[1],std::ios::binary);assert(f);
 std::string raw(std::istreambuf_iterator<char>{f},{});
 std::span<const std::byte> bytes(reinterpret_cast<const std::byte*>(raw.data()),raw.size());
 auto segments=nhk::elf::parse_program_segments(bytes);assert(segments);
 uint64_t extent=0;for(auto&s:*segments)if(s.type==nhk::elf::kProgramTypeLoad)extent=std::max(extent,s.vaddr+s.memsz);
 std::vector<std::byte> mapped(extent);Image image{};image.base=reinterpret_cast<uintptr_t>(mapped.data());
 assert(std::strlen(argv[1])<sizeof(image.path));std::strcpy(image.path,argv[1]);
 struct stat st{};assert(stat(argv[1],&st)==0);image.sourceDevice=st.st_dev;image.sourceInode=st.st_ino;image.fileViewBytes=st.st_size;
 for(auto&s:*segments)if(s.type==nhk::elf::kProgramTypeLoad){
  std::memcpy(mapped.data()+s.vaddr,bytes.data()+s.offset,s.filesz);
  image.segments[image.segmentCount++]={image.base+s.vaddr,image.base+s.vaddr+s.memsz,s.flags};
 }
 const bool loaded=SymbolIndex::Instance().EnsureLoaded(image);std::cerr<<"symbol index: "<<SymbolIndex::Instance().status()<<"\n";assert(loaded);SetForceSymbolOnlyForTest(true);CodeView code(image);
 Config c{};c.flags=1;c.enabled={kFeatureFolderCols};c.folderCols=5;LocatedSites sites{};LocateSites(code,c,&sites);
 assert(sites.ok16&&sites.colsReadCount==1&&!sites.ok16sq);
 assert(ValidateSitesShape(code,sites)&&ValidateSites(code,sites));
 for(uint32_t cols:{0u,1u,3u,4u,5u,6u,16u}){
  c.folderCols=cols;PlanResult plan{};DerivePatches(code,c,sites,&plan);
  if(cols>=4&&cols<=6){assert(plan.ok16&&plan.patches.size()==1);auto&p=plan.patches[0];assert(p.va==sites.colsReadVa[0]&&p.expect==0x91001800);}
  else assert(plan.patches.empty());
 }
 c.folderCols=5;PlanResult p{};DerivePatches(code,c,sites,&p);assert(p.patches.size()==1);
 auto original=mapped;auto patch=p.patches[0];std::memcpy(mapped.data()+patch.va,&patch.patch,4);
 assert(ValidateSitesShape(code,sites)&&ValidateSites(code,sites));
 c.folderCols=3;p={};DerivePatches(code,c,sites,&p);assert(p.patches.size()==1&&p.patches[0].patch==0x91001800);
 mapped=original; // same capacity/address: CodeView still points to mapped storage
 auto corrupt=[&](uint32_t at){uint32_t w;std::memcpy(&w,mapped.data()+at,4);w^=1;std::memcpy(mapped.data()+at,&w,4);};
 for(uint32_t at:{sites.storeVa,sites.storeVa+12}){corrupt(at);assert(!ValidateSitesShape(code,sites)&&!ValidateSites(code,sites));corrupt(at);}
 LocatedSites legacy=sites;legacy.colsThreadLoad=0xf9400340;assert(!ValidateSitesShape(code,legacy)&&!ValidateSites(code,legacy));
 std::vector<uint8_t> cache;assert(SerializeSites(sites,&cache));LocatedSites round{};assert(ParseSites(cache.data(),cache.size(),&round));assert(ValidateSitesShape(code,round));
 // Our producer splice may precede cache validation or even fresh getter discovery.
 // Its live absolute jump must not poison the original-source geometry contract.
 uint32_t producer=0,producerSize=0;
 assert(SymbolIndex::Instance().Find("FolderConfigHandler.handle",&producer,&producerSize));
 const uint32_t jump[4]={0x58000050,0xd61f0200,0x12345000,0x00000070};
 std::memcpy(mapped.data()+producer+0x32c,jump,sizeof(jump));
 assert(ValidateSitesShape(code,round)&&ValidateSites(code,round));
 LocatedSites afterHook{};c.flags=1;c.folderCols=5;LocateSites(code,c,&afterHook);
 assert(afterHook.ok16&&afterHook.colsReadCount==1);
 p={};DerivePatches(code,c,afterHook,&p);assert(p.ok16&&p.patches.size()==1);
 // Source verification is mandatory: a changed/missing inode is not a fallback
 // to the patched live body, even when a valid serialized plan already exists.
 Image wrong=image;wrong.sourceInode^=1;CodeView wrongCode(wrong);
 assert(!ValidateSitesShape(wrongCode,round)&&!ValidateSites(wrongCode,round));
 uint32_t old=10;std::memcpy(cache.data(),&old,4);assert(!ParseSites(cache.data(),cache.size(),&round));
 c.flags=0;c.folderCols=5;p={};DerivePatches(code,c,sites,&p);assert(p.patches.empty());
 std::cout<<"PASS real ELF getter-only planner, columns/default/master, restore, both cache guards, legacy cache rejection\n";
}
