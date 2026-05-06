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

    context "when arch is ARCH_MIPS64LE" do
      let(:arch) { Rex::Arch::ARCH_MIPS64LE }
      let(:addr) { 0x4142434445464748 }
      it "packs addr as 64-bit unsigned, little-endian" do
        is_expected.to eq("HGFEDCBA")
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

    context "when arch is ARCH_PPCE500V2" do
      let(:arch) { Rex::Arch::ARCH_PPCE500V2 }
      let(:addr) { 0x41424344 }
      it "packs addr as 32-bit unsigned, big-endian" do
        is_expected.to eq("ABCD")
      end
    end

    context "when arch is ARCH_SPARC" do
      let(:arch) { Rex::Arch::ARCH_SPARC }
      let(:addr) { 0x41424344 }
      it "packs addr as 32-bit unsigned, big-endian" do
        is_expected.to eq("ABCD")
      end
    end

    context "when arch is ARCH_SPARC64" do
      let(:arch) { Rex::Arch::ARCH_SPARC64 }
      let(:addr) { 0x4142434445464748 }
      it "packs addr as 64-bit unsigned, big-endian" do
        is_expected.to eq("ABCDEFGH")
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

    context "when arch is ARCH_ZARCH" do
      let(:arch) { Rex::Arch::ARCH_ZARCH }
      let(:addr) { 0x4142434445464748 }
      it "packs addr as 64-bit unsigned, big-endian" do
        is_expected.to eq("ABCDEFGH")
      end
    end

    context "when arch is ARCH_RISCV32BE" do
      let(:arch) { Rex::Arch::ARCH_RISCV32BE }
      let(:addr) { 0x41424344 }
      it "packs addr as 32-bit unsigned, big-endian" do
        is_expected.to eq("ABCD")
      end
    end

    context "when arch is ARCH_RISCV32LE" do
      let(:arch) { Rex::Arch::ARCH_RISCV32LE }
      let(:addr) { 0x41424344 }
      it "packs addr as 32-bit unsigned, little-endian" do
        is_expected.to eq("DCBA")
      end
    end

    context "when arch is ARCH_RISCV64BE" do
      let(:arch) { Rex::Arch::ARCH_RISCV64BE }
      let(:addr) { 0x4142434445464748 }
      it "packs addr as 64-bit unsigned, big-endian" do
        is_expected.to eq("ABCDEFGH")
      end
    end

    context "when arch is ARCH_RISCV64LE" do
      let(:arch) { Rex::Arch::ARCH_RISCV64LE }
      let(:addr) { 0x4142434445464748 }
      it "packs addr as 64-bit unsigned, little-endian" do
        is_expected.to eq("HGFEDCBA")
      end
    end

    context "when arch is ARCH_LOONGARCH64" do
      let(:arch) { Rex::Arch::ARCH_LOONGARCH64 }
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
        Rex::Arch::ARCH_X64 => Rex::Arch::ENDIAN_LITTLE,
        Rex::Arch::ARCH_MIPS => Rex::Arch::ENDIAN_BIG,
        Rex::Arch::ARCH_MIPSLE => Rex::Arch::ENDIAN_LITTLE,
        Rex::Arch::ARCH_MIPSBE => Rex::Arch::ENDIAN_BIG,
        Rex::Arch::ARCH_MIPS64 => Rex::Arch::ENDIAN_BIG,
        Rex::Arch::ARCH_MIPS64LE => Rex::Arch::ENDIAN_LITTLE,
        Rex::Arch::ARCH_PPC => Rex::Arch::ENDIAN_BIG,
        Rex::Arch::ARCH_PPC64LE => Rex::Arch::ENDIAN_LITTLE,
        Rex::Arch::ARCH_PPCE500V2 => Rex::Arch::ENDIAN_BIG,
        Rex::Arch::ARCH_SPARC => Rex::Arch::ENDIAN_BIG,
        Rex::Arch::ARCH_SPARC64 => Rex::Arch::ENDIAN_BIG,
        Rex::Arch::ARCH_ARMLE => Rex::Arch::ENDIAN_LITTLE,
        Rex::Arch::ARCH_ARMBE => Rex::Arch::ENDIAN_BIG,
        Rex::Arch::ARCH_AARCH64 => Rex::Arch::ENDIAN_LITTLE,
        Rex::Arch::ARCH_RISCV32BE => Rex::Arch::ENDIAN_BIG,
        Rex::Arch::ARCH_RISCV32LE => Rex::Arch::ENDIAN_LITTLE,
        Rex::Arch::ARCH_RISCV64BE => Rex::Arch::ENDIAN_BIG,
        Rex::Arch::ARCH_RISCV64LE => Rex::Arch::ENDIAN_LITTLE,
        Rex::Arch::ARCH_LOONGARCH64 => Rex::Arch::ENDIAN_LITTLE,
        Rex::Arch::ARCH_ZARCH => Rex::Arch::ENDIAN_BIG,
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

  describe ".from_uname" do
    subject { described_class.from_uname(uname_arch) }

    context "when uname_arch is x86_64" do
      let(:uname_arch) { 'x86_64' }
      it { is_expected.to eq(Rex::Arch::ARCH_X86_64) }
    end

    context "when uname_arch is amd64" do
      let(:uname_arch) { 'amd64' }
      it { is_expected.to eq(Rex::Arch::ARCH_X86_64) }
    end

    context "when uname_arch is i686" do
      let(:uname_arch) { 'i686' }
      it { is_expected.to eq(Rex::Arch::ARCH_X86) }
    end

    context "when uname_arch is i386" do
      let(:uname_arch) { 'i386' }
      it { is_expected.to eq(Rex::Arch::ARCH_X86) }
    end

    context "when uname_arch is aarch64" do
      let(:uname_arch) { 'aarch64' }
      it { is_expected.to eq(Rex::Arch::ARCH_AARCH64) }
    end

    context "when uname_arch is arm64" do
      let(:uname_arch) { 'arm64' }
      it { is_expected.to eq(Rex::Arch::ARCH_AARCH64) }
    end

    context "when uname_arch is armv7l" do
      let(:uname_arch) { 'armv7l' }
      it { is_expected.to eq(Rex::Arch::ARCH_ARMLE) }
    end

    context "when uname_arch is armv7b" do
      let(:uname_arch) { 'armv7b' }
      it { is_expected.to eq(Rex::Arch::ARCH_ARMBE) }
    end

    context "when uname_arch is mips" do
      let(:uname_arch) { 'mips' }
      it { is_expected.to eq(Rex::Arch::ARCH_MIPSBE) }
    end

    context "when uname_arch is mipsel" do
      let(:uname_arch) { 'mipsel' }
      it { is_expected.to eq(Rex::Arch::ARCH_MIPSLE) }
    end

    context "when uname_arch is mips64" do
      let(:uname_arch) { 'mips64' }
      it { is_expected.to eq(Rex::Arch::ARCH_MIPS64) }
    end

    context "when uname_arch is mips64el" do
      let(:uname_arch) { 'mips64el' }
      it { is_expected.to eq(Rex::Arch::ARCH_MIPS64LE) }
    end

    context "when uname_arch is ppc" do
      let(:uname_arch) { 'ppc' }
      it { is_expected.to eq(Rex::Arch::ARCH_PPC) }
    end

    context "when uname_arch is ppc64" do
      let(:uname_arch) { 'ppc64' }
      it { is_expected.to eq(Rex::Arch::ARCH_PPC64) }
    end

    context "when uname_arch is ppc64le" do
      let(:uname_arch) { 'ppc64le' }
      it { is_expected.to eq(Rex::Arch::ARCH_PPC64LE) }
    end

    context "when uname_arch is s390x" do
      let(:uname_arch) { 's390x' }
      it { is_expected.to eq(Rex::Arch::ARCH_ZARCH) }
    end

    context "when uname_arch is sparc" do
      let(:uname_arch) { 'sparc' }
      it { is_expected.to eq(Rex::Arch::ARCH_SPARC) }
    end

    context "when uname_arch is sparc64" do
      let(:uname_arch) { 'sparc64' }
      it { is_expected.to eq(Rex::Arch::ARCH_SPARC64) }
    end

    context "when uname_arch is riscv64" do
      let(:uname_arch) { 'riscv64' }
      it { is_expected.to eq(Rex::Arch::ARCH_RISCV64LE) }
    end

    context "when uname_arch is loongarch64" do
      let(:uname_arch) { 'loongarch64' }
      it { is_expected.to eq(Rex::Arch::ARCH_LOONGARCH64) }
    end

    context "when uname_arch has leading/trailing whitespace" do
      let(:uname_arch) { '  x86_64  ' }
      it { is_expected.to eq(Rex::Arch::ARCH_X86_64) }
    end

    context "when uname_arch is unrecognized" do
      let(:uname_arch) { 'unknown_arch' }
      it { is_expected.to be_nil }
    end
  end

end