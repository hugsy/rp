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
#include "main.hpp"
#include "coloshell.hpp"
#include "program.hpp"
#include "toolbox.hpp"
//#include "argtable3.h"

#include "cxxopts.hpp"


#include <iostream>
#include <exception>
#include <cstdlib>
#include <cstring>



int main(int argc, char* argv[])
{
    auto colors = true;
    auto show_version = false;
    auto show_help = false;
    size_t n_max_thread = 2;
    

    cxxopts::Options options(argv[0], "rp++ allows you to find ROP gadgets in pe/elf/mach-o x86/x64/ARM binaries. NB: The original idea comes from (@jonathansalwan) and his 'ROPGadget' tool.\n");
    options
        .show_positional_help();

    // todo: use groups?

    options.add_options()

        //
        // modes
        //
        ("i,info", "display information about the binary header", cxxopts::value<int>())
        ("r,rop", "find useful gadget for your future exploits, arg is the gadget maximum size in instructions", cxxopts::value<int>())


        ("raw", "find gadgets in a raw file, 'archi' must be in the following list: x86, x64", cxxopts::value<std::string>())
        ("max-thread", "set the maximum number of threads that can be used (default: 2)", cxxopts::value<size_t>(n_max_thread))
        ("thumb", "enable thumb mode when looking for ARM gadgets", cxxopts::value<bool>()->default_value("false"))
        ("image-base", "don't use the image base of the binary, but yours instead", cxxopts::value<std::string>(), "<0xdeadbeef>")


        //
        // search
        //
        ("search-int", "try to find a pointer on a specific integer value", cxxopts::value<std::string>(), "<int in hex>")
        ("search-hexa", "try to find hex values", cxxopts::value<std::string>(), "<\\x90A\\x90>")


        //
        // filter
        //
        ("unique", "display only unique gadget", cxxopts::value<bool>()->default_value("false"))
        ("bad-bytes", "the bytes you don't want to see in the gadgets' addresses", cxxopts::value<std::string>(), "<\\x90A\\x90>")


        //
        // misc
        //
        ("colors", "enable colors", cxxopts::value<bool>(colors))
        ("h,help", "print this help and exit", cxxopts::value<bool>(show_help))
        ("v,version", "print version information and exit", cxxopts::value<bool>(show_version))
        ("d,debug", "Enable debugging")

        ("binary_files", "binary path", cxxopts::value<std::vector<std::string>>())
        ;


    try
    {
        options.parse_positional({ "binary_files" });
        auto args = options.parse(argc, argv);

        if (colors)
            g_colors_desired = true;


        if (show_version)
            std::cout << "You are currently using the version " << VERSION << " of rp++." << std::endl;

        else if (args.count("binary_files") == 0)
            show_help = true;

        if(show_help)
        {
            std::cout << options.help({""}) << std::endl;
            std::cout << std::endl;
        }

        /* If we've asked the help or version option, we assume the program is terminated */
        if(show_version || show_help)
            return 0;

        if(args.count("binary_files"))
        {
            auto positional_arguments = args["binary_files"].as<std::vector<std::string>>();
            // todo : handle multiple files? 

            std::string program_path{ positional_arguments.at(0) };
            CPU::E_CPU arch(CPU::CPU_UNKNOWN);

            if(args.count("raw"))
            {
                const char* architecture = args["raw"].as<std::string>().c_str();

                if(std::strcmp(architecture, "x86") == 0)
                    arch = CPU::CPU_x86;
                else if(std::strcmp(architecture, "x64") == 0)
                    arch = CPU::CPU_x64;
				else if(std::strcmp(architecture, "arm") == 0)
					arch = CPU::CPU_ARM;
                else
                    RAISE_EXCEPTION("You must use an architecture supported, read the help");
                
            }
            
            Program p(program_path, arch);

            {
                auto level = args.count("debug");
                VerbosityLevel verbose_level;

                switch (level)
                {
                    case 1:
                    case 2:
                    case 3:
                        verbose_level = (VerbosityLevel)level;
                        break;

                    default: 
                        verbose_level = VERBOSE_LEVEL_1;
                        break;
                }

                if (level)
                    p.display_information((VerbosityLevel)verbose_level);
            }


            if(args.count("rop"))
            {
                auto rop = args["rop"].as<int>();

                if(rop < 0)
                    rop = 0;

                if(rop > MAXIMUM_INSTRUCTION_PER_GADGET)
                    RAISE_EXCEPTION("You specified a maximum number of instruction too important for the --rop option");

				uint32_t options = 0;
				if(args.count("thumb"))
					options |= (uint32_t)RpFindGadgetFlag::RP_ARM_USE_THUMB_MODE;

               
                if(n_max_thread == 0)
                    n_max_thread = 2;


                std::cout << std::endl << "Wait a few seconds, rp++ is looking for gadgets (" << n_max_thread << " threads max).." << std::endl;
                std::multiset<std::shared_ptr<Gadget>> all_gadgets;
                p.find_gadgets(rop, all_gadgets, options, n_max_thread);

                // Here we set the base beeing 0 if we want to have absolute virtual memory address displayed
                uint64_t base = 0;
                uint64_t new_base = 0;
                if( args.count("image-base"))
                {
                    // If not we will substract the base address to every gadget to keep only offsets
                    base = p.get_image_base_address();
                    // And we will use your new base address
                    auto va= args["image-base"].as<std::string>();
                    new_base = strtoul(va.c_str(), nullptr, 16); 
                }

                std::cout << "A total of " << all_gadgets.size() << " gadgets found." << std::endl;
                std::vector<uint8_t> badbyte_list;

                if (args.count("bad-bytes"))
                {
                    auto badbytes = args["bad-bytes"].as<std::string>();
                    badbyte_list = string_to_hex(badbytes.c_str());
                }

                uint64_t nb_gadgets_filtered = 0;
                if(args.count("unique"))
                {
                    std::set<std::shared_ptr<Gadget>, Gadget::Sort> unique_gadgets;
                    only_unique_gadgets(all_gadgets, unique_gadgets);

                    std::cout << "You decided to keep only the unique ones, " << unique_gadgets.size() << " unique gadgets found." << std::endl;

                    /* Now we walk the gadgets found and set the VA */
                    for(const auto &unique_gadget : unique_gadgets)
                        display_gadget_lf(unique_gadget->get_first_absolute_address(), unique_gadget);
                }
                else
                {
                    for(const auto &gadget : all_gadgets)
                        display_gadget_lf(gadget->get_first_absolute_address(), gadget);
                }

                if(args.count("badbytes"))
                    std::cout << std::endl << nb_gadgets_filtered << " gadgets have been filtered because of your bad-bytes." << std::endl;
            }

            if(args.count("search-hexa"))
            {
                auto shexa = args["search-hexa"].as<std::string>();
                std::vector<uint8_t> hex_values = string_to_hex(shexa.c_str());
                p.search_and_display(hex_values.data(), (uint32_t)hex_values.size());
            }
            
            if(args.count("search-int"))
            {
                auto sint = args["search-int"].as<std::string>();
                uint32_t val = std::strtoul(sint.c_str(), nullptr, 16);
                p.search_and_display((const uint8_t*)&val, sizeof(uint32_t));
            }
        }
    }
    catch(const std::exception &e)
    {
        enable_color(COLO_RED);
        std::cout << e.what() << std::endl;
        disable_color();
    }

    return 0;
}
