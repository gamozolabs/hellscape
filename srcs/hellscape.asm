; HELLSCAPE
;
; A unit testing framework for verifying a fuzzer can brute through multiple
; primitives using generic feedback using purely byte level random corruption.
;
; No static analysis or specialized fuzzers are allowed!
;

[bits 32]

; Address to read to trigger a crash
%define CRASH_ADDR 0xdeadbeef

section .code

global mainCRTStartup
mainCRTStartup:
	; Get a pointer to the payload (always 32 bytes), add 4 to it to skip
	; over the switching byte but also maintain alignment
	mov ebx, payload
	add ebx, 4

	; The next compares switch against the first byte in the payload. This
	; will change the test case we end up fuzzing. Code coverage should pick
	; up that there are unique cases based on this first byte and make it
	; easy for this switch to be enumerated.

	cmp byte [ebx - 4], 0
	je  fuzz_unique_coverage

	cmp byte [ebx - 4], 1
	je  fuzz_unique_byte_memcmp

	cmp byte [ebx - 4], 2
	je  fuzz_unique_byte_memcmp_twice

	cmp byte [ebx - 4], 3
	je  fuzz_dword_cmp

	cmp byte [ebx - 4], 4
	je  fuzz_dword_memcmp

	cmp byte [ebx - 4], 5
	je  fuzz_dword_memcmp_twice

	; Exit the program
	xor eax, eax
	ret

; __stdcall (callee cleans up stack)
; int memory_matches_bytes(const uint8_t *a1, const uint8_t *a2, size_t length)
; 
; Compare a1 to a2 of length (in bytes). Returns number of matching bytes
;
; This compare performs the comparison at a byte level
;
global memory_matches_bytes
memory_matches_bytes:
	push edi
	push esi
	
	mov edi, dword [esp + 0x8 + 0x04] ; a1
	mov esi, dword [esp + 0x8 + 0x08] ; a2
	mov ecx, dword [esp + 0x8 + 0x0c] ; length (in bytes)

	xor eax, eax

.lewp:
	mov  dl, byte [edi]
	cmp  byte [esi], dl
	mov  edx, 0
	sete dl
	add  eax, edx

	add edi, 1
	add esi, 1
	sub ecx, 1
	jnz short .lewp

.match:
	pop esi
	pop edi
	ret 0xc

; __stdcall (callee cleans up stack)
; int memory_matches_dwords(const uint32_t *a1, const uint32_t *a2, size_t dwords)
;
; Returns number of matching dwords
;
; This compare performs the comparison at a dword level
;
global memory_matches_dwords
memory_matches_dwords:
	push edi
	push esi
	
	mov edi, dword [esp + 0x8 + 0x04] ; a1
	mov esi, dword [esp + 0x8 + 0x08] ; a2
	mov ecx, dword [esp + 0x8 + 0x0c] ; length (in number of dwords)

	xor eax, eax

.lewp:
	mov  edx, dword [edi]
	cmp  dword [esi], edx
	mov  edx, 0
	sete dl
	add  eax, edx

	add edi, 4
	add esi, 4
	sub ecx, 1
	jnz short .lewp

.match:
	pop esi
	pop edi
	ret 0xc

; Perform byte compares on the input, branching uniquely on each compare.
;
; This searches for the string "MAGICSTRING", and crashes by reading
; CRASH_ADDR if it matches.
;
; Finding method:
;
; Unique code coverage will happen every time a byte matches. This will cause
; inputs to be saved each time we get a byte further and this will easily be
; found with only code coverage.
;
global fuzz_unique_coverage
fuzz_unique_coverage:
	cmp byte [ebx + 0], 'M'
	jne short .no_match

	cmp byte [ebx + 1], 'A'
	jne short .no_match

	cmp byte [ebx + 2], 'G'
	jne short .no_match

	cmp byte [ebx + 3], 'I'
	jne short .no_match

	cmp byte [ebx + 4], 'C'
	jne short .no_match

	cmp byte [ebx + 5], 'S'
	jne short .no_match

	cmp byte [ebx + 6], 'T'
	jne short .no_match

	cmp byte [ebx + 7], 'R'
	jne short .no_match

	cmp byte [ebx + 8], 'I'
	jne short .no_match

	cmp byte [ebx + 9], 'N'
	jne short .no_match

	cmp byte [ebx + 10], 'G'
	jne short .no_match

	; Force crash by reading CRASH_ADDR
	mov al, byte [CRASH_ADDR]

.no_match:
	xor eax, eax
	ret

; Perform byte level comparison using a memcmp-like primitive. This uses the
; same code to compare the bytes in a loop thus just pure code coverage is
; not enough to solve this.
;
; It is expected here that register coverage will pick up on the unique loop
; counter of memcmp which will allow feedback each time we get one byte further
; through processing the input
;
global fuzz_unique_byte_memcmp
fuzz_unique_byte_memcmp:
	push fuzz_unique_byte_memcmp_trigger_len
	push fuzz_unique_byte_memcmp_trigger
	push ebx
	call memory_matches_bytes
	cmp  eax, fuzz_unique_byte_memcmp_trigger_len
	jne  short .no_match

	; Force crash by reading CRASH_ADDR
	mov al, byte [CRASH_ADDR]

.no_match:
	xor eax, eax
	ret

; Perform byte level comparison using a memcmp-like primitive. This uses
; the same code to compare bytes in a loop, but also performs two memcmps.
; This results in register coverage no longer working with PC tagging as the
; matching register state was already observed and will not trigger on the
; second memcmp.
;
; This test is to stress that register coverage is tagged with something path
; aware such as a hash of cumulative branches or call stack information.
; Without this the second memcmp will trigger no unique coverage
;
global fuzz_unique_byte_memcmp_twice
fuzz_unique_byte_memcmp_twice:
	push fuzz_unique_byte_memcmp_twice_trigger_a_len
	push fuzz_unique_byte_memcmp_twice_trigger_a
	push ebx
	call memory_matches_bytes
	cmp  eax, fuzz_unique_byte_memcmp_twice_trigger_a_len
	jne  short .no_match

	add ebx, fuzz_unique_byte_memcmp_twice_trigger_a_len

	push fuzz_unique_byte_memcmp_twice_trigger_b_len
	push fuzz_unique_byte_memcmp_twice_trigger_b
	push ebx
	call memory_matches_bytes
	cmp  eax, fuzz_unique_byte_memcmp_twice_trigger_b_len
	jne  short .no_match

	; Force crash by reading CRASH_ADDR
	mov al, byte [CRASH_ADDR]

.no_match:
	xor eax, eax
	ret

; Simply compare the input against a magic value with a single 32-bit compare
;
; This requires partial compare coverage that allows for incremental progress
; through larger-than-byte compares
;
fuzz_dword_cmp:
	cmp dword [ebx], 0xea8f9587
	jne short .no_match

	; Force crash by reading CRASH_ADDR
	mov al, byte [CRASH_ADDR]

.no_match:
	xor eax, eax
	ret

; Compare against a constant string using dwords in a memcmp.
;
; Since the memcmp is done in a loop we need more than code coverage. Since
; the compares are done as dwords we need smarter than bruting.
;
; This is to test that register feedback works (for partial memcmp progress
; logging) and that partial dword comparison feedback is also working
;
fuzz_dword_memcmp:
	push fuzz_dword_memcmp_trigger_len / 4
	push fuzz_dword_memcmp_trigger
	push ebx
	call memory_matches_dwords
	cmp  eax, fuzz_dword_memcmp_trigger_len / 4
	jne  short .no_match

	; Force crash by reading CRASH_ADDR
	mov al, byte [CRASH_ADDR]

.no_match:
	xor eax, eax
	ret

; Compare against a constant string using dwords in a memcmp, but do two
; memcmps.
;
; Since the memcmp is done in a loop we need more than code coverage. Since
; the compares are done as dwords we need smarter than bruting. Since we do
; multiple memcmps we also need code flow hashing.
;
; This is to test that register feedback works (for partial memcmp progress
; logging) and that partial dword comparison feedback is also working. This
; also checks for code flow hashing to give unique tagging to different paths
; that hit the same code/register states.
;
fuzz_dword_memcmp_twice:
	push fuzz_dword_memcmp_twice_trigger_a_len / 4
	push fuzz_dword_memcmp_twice_trigger_a
	push ebx
	call memory_matches_dwords
	cmp  eax, fuzz_dword_memcmp_twice_trigger_a_len / 4
	jne  short .no_match

	add ebx, fuzz_dword_memcmp_twice_trigger_a_len

	push fuzz_dword_memcmp_twice_trigger_b_len / 4
	push fuzz_dword_memcmp_twice_trigger_b
	push ebx
	call memory_matches_dwords
	cmp  eax, fuzz_dword_memcmp_twice_trigger_b_len / 4
	jne  short .no_match

	; Force crash by reading CRASH_ADDR
	mov al, byte [CRASH_ADDR]

.no_match:
	xor eax, eax
	ret	

section .data

align 4
global fuzz_unique_byte_memcmp_twice_trigger_a
fuzz_unique_byte_memcmp_twice_trigger_a: db "MULTI"
fuzz_unique_byte_memcmp_twice_trigger_a_len: equ $ - fuzz_unique_byte_memcmp_twice_trigger_a

align 4
global fuzz_unique_byte_memcmp_twice_trigger_b
fuzz_unique_byte_memcmp_twice_trigger_b: db "memcmp()"
fuzz_unique_byte_memcmp_twice_trigger_b_len: equ $ - fuzz_unique_byte_memcmp_twice_trigger_b

align 4
global fuzz_unique_byte_memcmp_trigger
fuzz_unique_byte_memcmp_trigger: db "mEmCmPsArEhArD"
fuzz_unique_byte_memcmp_trigger_len: equ $ - fuzz_unique_byte_memcmp_trigger

; This trigger must be divisible by 4 in length
align 4
global fuzz_dword_memcmp_trigger
fuzz_dword_memcmp_trigger: db "aPPl3sta5t3g00d!"
fuzz_dword_memcmp_trigger_len: equ $ - fuzz_dword_memcmp_trigger

; This trigger must be divisible by 4 in length
align 4
global fuzz_dword_memcmp_twice_trigger_a
fuzz_dword_memcmp_twice_trigger_a: db "WuRDTWIC"
fuzz_dword_memcmp_twice_trigger_a_len: equ $ - fuzz_dword_memcmp_twice_trigger_a

; This trigger must be divisible by 4 in length
align 4
global fuzz_dword_memcmp_twice_trigger_b
fuzz_dword_memcmp_twice_trigger_b: db "EohNO!@#"
fuzz_dword_memcmp_twice_trigger_b_len: equ $ - fuzz_dword_memcmp_twice_trigger_b

; Trigger for case 0
;payload: db 0, 0, 0, 0, "MAGICSTRING"

; Trigger for case 1
;payload: db 1, 0, 0, 0, "mEmCmPsArEhArD"

; Trigger for case 2
;payload: db 2, 0, 0, 0, "MULTI", "memcmp()"

; Trigger for case 3
;payload: db 3, 0, 0, 0, 0x87, 0x95, 0x8f, 0xea

; Trigger for case 4
;payload: db 4, 0, 0, 0, "aPPl3sta5t3g00d!"

; Trigger for case 5
;payload: db 5, 0, 0, 0, "WuRDTWICEohNO!@#"

align 4
global payload
payload:
times 32-($-payload) db 0

