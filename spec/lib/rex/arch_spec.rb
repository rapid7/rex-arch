# -*- coding:binary -*-
require 'spec_helper'

require 'rex/text'
require 'rex/arch'

RSpec.describe Rex::Arch do

  describe ".adjust_stack_pointer" do
    subject { described_class.adjust_stack_pointer(arch, adjustment) }
    let(:adjustment) { 100 }

    context "when arch is ARCH_X86" do
      let(:arch) { Rex::Arch::ARCH_X86 }

      it "emits an ESP adjustment instruction" do
        is_expected.to be_a_kind_of(String)
      end
    end

    context "when arch isn't ARCH_X86" do
      let(:arch) { Rex::Arch::ARCH_FIREFOX }

      it "returns nil" do
        is_expected.to be_nil
      end
    end

    context "when arch is an array" do
      let(:arch) { [Rex::Arch::ARCH_X86, Rex::Arch::ARCH_FIREFOX] }

      it "uses the first arch in the array" do
        is_expected.to be_a_kind_of(String)
      end
    end
  end

  describe ".pack_addr" do
    subject { described_class.pack_addr(arch, addr) }

    context "when arch is ARCH_X86" do
      let(:arch) { Rex::Arch::ARCH_X86 }
      let(:addr) { 0x41424344 }
      it "packs addr as 32-bit unsigned, little-endian" do
        is_expected.to eq("DCBA")
      end
    end

    context "when arch is ARCH_X86_64" do
      let(:arch) { Rex::Arch::ARCH_X86_64 }
      let(:addr) { 0x4142434445464748 }
      it "packs addr as 62-bit unsigned, little-endian" do
        is_expected.to eq("HGFEDCBA")
      end
    end

    context "when arch is ARCH_X64" do
      let(:arch) { Rex::Arch::ARCH_X64 }
      let(:addr) { 0x4142434445464748 }
      it "packs addr as 62-bit unsigned, little-endian" do
        is_expected.to eq("HGFEDCBA")
      end
    end

    context "when arch is ARCH_MIPS" do
      let(:arch) { Rex::Arch::ARCH_MIPS }
      let(:addr) { 0x41424344 }
      it "packs addr as 32-bit unsigned, big-endian" do
        is_expected.to eq("ABCD")
      end
    end

    context "when arch is ARCH_MIPSBE" do
      let(:arch) { Rex::Arch::ARCH_MIPSBE }
      let(:addr) { 0x41424344 }
      it "packs addr as 32-bit unsigned, big-endian" do
        is_expected.to eq("ABCD")
      end
    end

    context "when arch is ARCH_MIPSLE" do
      let(:arch) { Rex::Arch::ARCH_MIPSLE }
      let(:addr) { 0x41424344 }
      it "packs addr as 32-bit unsigned, little-endian" do
        is_expected.to eq("DCBA")
      end
    end

    context "when arch is ARCH_MIPS64" do
      let(:arch) { Rex::Arch::ARCH_MIPS64 }
      let(:addr) { 0x4142434445464748 }
      it "packs addr as 64-bit unsigned, big-endian" do
        is_expected.to eq("ABCDEFGH")
      end
    end

    context "when arch is ARCH_PPC" do
      let(:arch) { Rex::Arch::ARCH_PPC }
      let(:addr) { 0x41424344 }
      it "packs addr as 32-bit unsigned, big-endian" do
        is_expected.to eq("ABCD")
      end
    end

    context "when arch is ARCH_PPC64LE" do
      let(:arch) { Rex::Arch::ARCH_PPC64LE }
      let(:addr) { 0x4142434445464748 }
      it "packs addr as 64-bit unsigned, little-endian" do
        is_expected.to eq("HGFEDCBA")
      end
    end

    context "when arch is ARCH_SPARC" do
      let(:arch) { Rex::Arch::ARCH_SPARC }
      let(:addr) { 0x41424344 }
      it "packs addr as 32-bit unsigned, big-endian" do
        is_expected.to eq("ABCD")
      end
    end

    context "when arch is ARCH_ARMLE" do
      let(:arch) { Rex::Arch::ARCH_ARMLE }
      let(:addr) { 0x41424344 }
      it "packs addr as 32-bit unsigned, little-endian" do
        is_expected.to eq("DCBA")
      end
    end

    context "when arch is ARCH_ARMBE" do
      let(:arch) { Rex::Arch::ARCH_ARMBE }
      let(:addr) { 0x41424344 }
      it "packs addr as 32-bit unsigned, big-endian" do
        is_expected.to eq("ABCD")
      end
    end

    context "when arch is ARCH_AARCH64" do
      let(:arch) { Rex::Arch::ARCH_AARCH64 }
      let(:addr) { 0x4142434445464748 }
      it "packs addr as 64-bit unsigned, little-endian" do
        is_expected.to eq("HGFEDCBA")
      end
    end

    context "when arch is invalid" do
      let(:arch) { Rex::Arch::ARCH_FIREFOX }
      let(:addr) { 0x41424344 }

      it "packs addr as 32-bit unsigned, big-endian" do
        is_expected.to be_nil
      end
    end

    context "when arch is an Array" do
      let(:arch) { [Rex::Arch::ARCH_ARMLE, Rex::Arch::ARCH_ARMBE, Rex::Arch::ARCH_X86_64] }
      let(:addr) { 0x41424344 }
      it "packs addr using the first architecture in the array" do
        is_expected.to eq("DCBA")
      end
    end
  end

  describe ".endian" do

    let(:endianesses) do
      {
        Rex::Arch::ARCH_X86 => Rex::Arch::ENDIAN_LITTLE,
        Rex::Arch::ARCH_X86_64 => Rex::Arch::ENDIAN_LITTLE,
        Rex::Arch::ARCH_MIPS => Rex::Arch::ENDIAN_BIG,
        Rex::Arch::ARCH_MIPSLE => Rex::Arch::ENDIAN_LITTLE,
        Rex::Arch::ARCH_MIPSBE => Rex::Arch::ENDIAN_BIG,
        Rex::Arch::ARCH_MIPS64 => Rex::Arch::ENDIAN_BIG,
        Rex::Arch::ARCH_PPC => Rex::Arch::ENDIAN_BIG,
        Rex::Arch::ARCH_PPC64LE => Rex::Arch::ENDIAN_LITTLE,
        Rex::Arch::ARCH_SPARC => Rex::Arch::ENDIAN_BIG,
        Rex::Arch::ARCH_ARMLE => Rex::Arch::ENDIAN_LITTLE,
        Rex::Arch::ARCH_ARMBE => Rex::Arch::ENDIAN_BIG,
        Rex::Arch::ARCH_AARCH64 => Rex::Arch::ENDIAN_LITTLE
      }
    end
    subject { described_class.endian(arch) }

    context "when recognized arch" do
      it "returns its endianess" do
        endianesses.each_key do |arch|
          expect(described_class.endian(arch)).to eq(endianesses[arch])
        end
      end
    end

    context "when not recognized arch" do
      let(:arch) { Rex::Arch::ARCH_FIREFOX }
      it "returns ENDIAN_LITTLE" do
        is_expected.to eq(Rex::Arch::ENDIAN_LITTLE)
      end
    end

    context "when arch is an array" do
      let(:arch) { [Rex::Arch::ARCH_X86, Rex::Arch::ARCH_MIPSBE] }
      it "returns first arch endianess" do
        is_expected.to eq(Rex::Arch::ENDIAN_LITTLE)
      end
    end
  end
end
