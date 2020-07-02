#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <string>
#include <vector>

#include <bfd.h>
#include "lodestone.h"
static bfd* open_bfd(std::string &fname);
static int load_binary_bfd(std::string &fname, Binary *bin, Binary::BinType type);
static int load_symbols_bfd(bfd* bfd_h, Binary* bin);
static int load_dynsym_bfd(bfd* bfd_h, Binary* bin);
static int load_sections_bfd(bfd* bfd_h, Binary* bin);

static bfd* open_bfd(std::string &fname)
{
	static bool init_bfd = 0;
	bfd* bfd_h;
	
	//has bfd been spun up?
	if(!init_bfd)
	{
		//no? initialize
		bfd_init();
		init_bfd = 1;
	}

	//handle for bfd data structure
	bfd_h = bfd_openr(fname.c_str(), NULL);
	
	//Did the file open?
	if(bfd_h == NULL)
	{
		fprintf(stderr, "Failed to open '%s' : %s", 
					 fname.c_str(),
					 bfd_errmsg(bfd_get_error()));
		return NULL;
	}

	//do we recognize the format? (executable, relocatable and shared objects only)
	if(!bfd_check_format(bfd_h, bfd_object))
	{
		fprintf(stderr, "'%s' doesn't feel like an executable  : %s", 
					 fname.c_str(),
					 bfd_errmsg(bfd_get_error()));
		return NULL;
	}

	//set error to no error to be sure 
	//check format doesn't start in an error state
	bfd_set_error(bfd_error_no_error);

	//do we recognize the flavor of the executable?
	if(bfd_get_flavour(bfd_h) == bfd_target_unknown_flavour)
	{
		fprintf(stderr, "'%s' doesn't look like anything I know  : %s", 
					 fname.c_str(),
					 bfd_errmsg(bfd_get_error()));
		return NULL;
	}

	return bfd_h;
}

static int load_symbols_bfd(bfd* bfd_h, Binary* bin) 
{
	long n, i, symcount;
	asymbol** symtab;
	Symbol* sym;

	symtab = NULL;

	n = bfd_get_symtab_upper_bound(bfd_h);
	if(n < 0)
	{
		fprintf(stderr, "Can't read symtab (%s)\n", 
						bfd_errmsg(bfd_get_error()));
		return -1;
	}
	else if (n)
	{
		symtab = (asymbol**) malloc(n);
		if(!symtab)
		{
			fprintf(stderr, "Out of ants!\n");
			return -1;
		}
		symcount = bfd_canonicalize_symtab(bfd_h, symtab);
		if(symcount < 0)
		{
			fprintf(stderr,"Can't read symtab (%s)\n",bfd_errmsg(bfd_get_error()));
			free(symtab);
			return -1;
		}
		for(i=0; i<symcount; i++)
		{
			if(symtab[i]->flags & BSF_FUNCTION)
			{
				bin->syms.push_back(Symbol());
				sym = &bin->syms.back();
				sym->type = Symbol::SYM_TYPE_FNC;
				sym->name = std::string(symtab[i]->name);
				sym->addr = bfd_asymbol_value(symtab[i]);
			}
		}
	}
	free(symtab);
	return 0;
}

static int load_dynsym_bfd(bfd* bfd_h, Binary* bin) 
{
	long n, i, symcount;
	asymbol** dynsym;
	Symbol *sym;

	dynsym = NULL;

	n = bfd_get_dynamic_symtab_upper_bound(bfd_h);
	if(n < 0)
	{
		fprintf(stderr, "Can't read dynamic symtab (%s)\n",
						bfd_errmsg(bfd_get_error()));
		return -1;
	}
	else if (n)
	{
		dynsym = (asymbol**)malloc(n);
		if(!dynsym)
		{
			fprintf(stderr, "Out of dynamic ants!\n");
			return -1;
		}
		symcount = bfd_canonicalize_dynamic_symtab(bfd_h, dynsym);
		if(symcount < 0)
		{
			fprintf(stderr, "Can't read dynamic symtab (%s)",
							bfd_errmsg(bfd_get_error()));
			free(dynsym);
			return -1;
		}
		for(i=0; i<symcount; i++)
		{
			if(dynsym[i]->flags & BSF_FUNCTION)
			{
				bin->syms.push_back(Symbol());
				sym = &bin->syms.back();
				sym->type = Symbol::SYM_TYPE_FNC;
				sym->name = std::string(dynsym[i]->name);
				sym->addr = bfd_asymbol_value(dynsym[i]);
			}
		}
	}
	free(dynsym);
	return 0;
}


static int load_sections_bfd(bfd* bfd_h, Binary* bin)
{
	int flags;
	uint64_t vma, size;
	const char *secname;
	asection* bfd_sec;
	Section* sec;
	Section::SecType type;

	for(bfd_sec = bfd_h->sections; bfd_sec; bfd_sec = bfd_sec->next)
	{
		flags = bfd_get_section_flags(bfd_h, bfd_sec);
		type = Section::SEC_TYPE_NONE;
		if(flags & SEC_CODE)
			type = Section::SEC_TYPE_CODE;
		else if (flags & SEC_DATA)
			type = Section::SEC_TYPE_DATA;
		else
			continue;

		vma 			= bfd_section_vma(bfd_h, bfd_sec);
		size 			= bfd_section_size(bfd_h, bfd_sec);
		secname 	= bfd_section_name(bfd_h, bfd_sec);
		if(!secname)
			secname = "<unnamed>";

		bin->secs.push_back(Section());
		sec = &bin->secs.back();

		sec->binary = bin;
		sec->name = std::string(secname);
		sec->vma = vma;
		sec->size = size;
		sec->bytes = (uint8_t*)malloc(size);
		if(!sec->bytes)
		{
			fprintf(stderr,"Out of ants!\n");
			return -1;
		}
		if(!bfd_get_section_contents(bfd_h, bfd_sec, sec->bytes, 0, size))
		{
			fprintf(stderr, "failed to read section: '%s' (%s)\n",
							secname, bfd_errmsg(bfd_get_error()));
			return -1;
		}
	}
	return 0;
}

static int load_binary_bfd(std::string &fname, Binary *bin, Binary::BinType type)
{
	int ret;
	bfd* bfd_h;
	const bfd_arch_info_type *bfd_info;

	bfd_h = NULL;
	bfd_h = open_bfd(fname);
	if(bfd_h == NULL)
	{
		return -1;
	}

	bin->filename = std::string(fname);
	bin->entry		= bfd_get_start_address(bfd_h);

	bin->type_str = std::string(bfd_h->xvec->name);
	switch(bfd_h->xvec->flavour)
	{
		case bfd_target_elf_flavour:
			bin->type = Binary::BIN_TYPE_ELF;
			break;
		case bfd_target_coff_flavour:
			bin->type = Binary::BIN_TYPE_PE;
			break;
		default:
			fprintf(stderr, "I don't understand %s\n", bfd_h->xvec->name);
			bfd_close(bfd_h);
			return -1;
	}

	bfd_info = bfd_get_arch_info(bfd_h);
	bin->arch_str = std::string(bfd_info->printable_name);
	switch(bfd_info->mach)
	{
		case bfd_mach_i386_i386:
			bin->arch = Binary::ARCH_X86;
			bin->bits = 32;
			break;
		case bfd_mach_x86_64:
			bin->arch = Binary::ARCH_X86;
			bin->bits = 64;
			break;
		default:
			fprintf(stderr, "what is %s?\n", bfd_info->printable_name);
			bfd_close(bfd_h);
			return -1;
	}

	load_symbols_bfd(bfd_h, bin);
	load_dynsym_bfd(bfd_h, bin);

	if(load_sections_bfd(bfd_h, bin) < 0)
	{
		fprintf(stderr, "What happened to the sections?\n");
		bfd_close(bfd_h);
		return -1;
	}

	bfd_close(bfd_h);
	return 0;
}

int load_bin(std::string &fname, Binary* bin, Binary::BinType type)
{
	return load_binary_bfd(fname,bin,type);
}

void unload_bin(Binary* bin)
{
	int i;
	Section* sec;

	for(i=0; i < bin->secs.size(); i++)
	{
		sec = &bin->secs[i];
		if(sec->bytes)
			free(sec->bytes);
	}
}
