/*
    This file is part of rp++.

    Copyright (C) 2014, Axel "0vercl0k" Souchet <0vercl0k at tuxfamily.org>
    All rights reserved.

    rp++ is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    rp++ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with rp++.  If not, see <http://www.gnu.org/licenses/>.
*/
#include "x86.hpp"
#include "rpexception.hpp"
#include "disassenginewrapper.hpp"
#include "safeint.hpp"
#include "intelbeaengine.hpp"
#include "ropsearch_algorithm.hpp"

#include <cstring>
#include <list>

std::string x86::get_class_name(void) const
{
    return std::string("x86");
}

void x86::find_gadget_in_memory(
    const unsigned char *p_memory, const unsigned long long size, const unsigned long long vaddr,
    const unsigned int depth, std::multiset<std::shared_ptr<Gadget>> &gadgets, unsigned int disass_engine_option,
    std::mutex &m
)
{
    //BeaRopGadgetFinder bea(BeaRopGadgetFinder::x86, depth);
    //bea.find_rop_gadgets(p_memory, size, vaddr, gadgets);
    IntelBeaEngine bea_engine(IntelBeaEngine::x86);
    DisassEngineWrapper &engine = bea_engine;
    find_rop_gadgets(p_memory, size, vaddr, depth, gadgets, engine, m);
}

unsigned int x86::get_size_biggest_instruction(void)
{
    // "On INTEL processors, (in IA-32 or intel 64 modes), instruction never exceeds 15 bytes." -- beaengine.org
    return 15;
}

unsigned int x86::get_alignement(void)
{
    return 1;
}
