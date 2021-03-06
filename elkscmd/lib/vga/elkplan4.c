/*
 * Copyright (c) 1999 Greg Haerr <greg@censoft.com>
 *
 * MicroWindows
 * ELKS EGA/VGA Screen Driver 16 color 4 planes - 16-bit assembly version
 * 
 * This file is an adapation of the asmplan4.s MSC asm driver for ELKS
 */
#include "vga_dev.h"
#include "vgaplan4.h"

/* assumptions for speed: NOTE: psd is ignored in these routines*/
#define SCREENSEG		$0a000
#define SCREENBASE 		MK_FP(0xa000, 0)
#define BYTESPERLINE		80

/* extern data*/
extern MODE gr_mode;	/* temp kluge*/

static unsigned char mode_table[MODE_MAX + 1] = {
  0x00, 0x18, 0x10, 0x08
};

int
ega_init(PSD psd)
{
	/* fill in screendevice struct*/
	psd->addr = SCREENBASE;
	psd->linelen = BYTESPERLINE;

	/* Set up some default values for the VGA Graphics Registers. */
	set_enable_sr (0x0f);
	set_op (0);
	set_mode (0);

	return 1;
}

/*
* Routine to draw a horizontal line.
*	ega_drawhine(psd, x1, x2, y, color);
*
*	works in the following EGA and VGA modes:
*	200 line 16 colors modes
*	350 line modes
*	640x480 16 color
*/
/* Draw horizontal line from x1,y to x2,y not including final point*/
void
ega_drawhorzline(PSD psd, int x1, int x2, int y, int color)
{
#asm
	push	bp		; setup stack frame and preserve registers
	mov	bp, sp
	push	si
	push	di
	push	es

	dec	[bp+8]		; dec x2 - don't draw final point
	; configure the graphics controller

	mov	dx, #$03ce	; DX := Graphics Controller port address
	
	mov	al, #3		; set data rotate register
	lea	bx, _mode_table
	add	bx, _gr_mode
	mov	ah, [bx]
	out	dx, ax

	mov 	ah, [bp+12]	; pixel value
	xor	al, al		; Set/Reset register number (0)
	out	dx, ax

	mov	ax, #$0f01	; AH := bit plane mask for Enable Set/Reset
	out	dx, ax		; AL := Enable Set/Reset register number

	push	ds		; preserve DS

	mov	ax, [bp+10]	; y
	mov	bx, [bp+6]	; x1

	; compute pixel address
	mov	dx, #BYTESPERLINE ; AX := [row * BYTESPERLINE]
	mul	dx
	mov 	cl, bl		; save low order column bits
	shr	bx, #1		; BX := [col / 8]
	shr	bx, #1
	shr	bx, #1
	add	bx, ax		; BX := [row * BYTESPERLINE] + [col / 8]
	and	cl, #$07	; CL := [col % 8]
	xor	cl, #$07	; CL := 7 - [col % 8]
	mov 	ah, #$01	; AH := 1 << [7 - [col % 8]]	[mask]
	mov	dx, #SCREENSEG	; ES := EGA buffer segment address
	mov	es, dx
				; AH := bit mask
				; ES:BX -> video buffer
				; CL := number bits to shift left
	mov	di, bx		; ES:DI -> buffer
	mov 	dh, ah		; DH := unshifted bit mask for left byte

	not	dh
	shl	dh, cl		; DH := reverse bit mask for first byte
	not	dh		; DH := bit mask for first byte

	mov	cx, [bp+8]	; x2
	and	cl, #7
	xor	cl, #7		; CL := number of bits to shift left
	mov 	dl, #$0ff	; DL := unshifted bit mask for right byte
	shl	dl, cl		; DL := bit mask for last byte

	; determine byte offset of first and last pixel in the line

	mov	ax, [bp+8]	; AX := x2
	mov	bx, [bp+6]	; BX := x1

	mov 	cl, #3		; bits to convert pixels to bytes

	shr	ax, cl		; AX := byte offset of X2
	shr	bx, cl		; BX := byte offset of X1
	mov	cx, ax
	sub	cx, bx		; CX := [number of bytes in line] - 1

	; get Graphics Controller port address into DX

	mov	bx, dx		; BH := bit mask for first byte
				; BL := bit mask for last byte
	mov	dx, #$03ce	; DX := Graphics Controller port
	mov 	al, #8		; AL := Bit mask Register number

	; make video buffer addressable through DS:SI

	push	es
	pop	ds
	mov	si, di		; DS:SI -> video buffer

	; set pixels in leftmost byte of the line

	or	bh, bh
	js	L43		; jump if byte-aligned [x1 is leftmost]

	or	cx, cx
	jnz	L42		; jump if more than one byte in the line

	and	bl, bh		; BL := bit mask for the line
	jmp near L44

L42:	mov 	ah, bh		; AH := bit mask for first byte
	out	dx, ax		; update graphics controller

	movsb			; update bit planes
	dec	cx

	; use a fast 8086 machine instruction to draw the remainder of the line

L43:	mov 	ah, #$0ff	; AH := bit mask
	out	dx, ax		; update Bit Mask register
	rep 
	movsb			; update all pixels in the line

	; set pixels in the rightmost byte of the line

L44:	mov 	ah, bl		; AH := bit mask for last byte
	out	dx, ax		; update Graphics Controller
	movsb			; update bit planes

	pop	ds		; restore ds

	; restore default Graphics Controller state and return to caller
	;;xor	ax, ax		; AH := 0, AL := 0
	;;out	dx, ax		; restore Set/Reset register
	;;inc	ax		; AH := 0, AL := 1
	;;out	dx, ax		; restore Enable Set/Reset register
	;;mov	ax, #$0ff08	; AH := 0xff, AL := 0
	;;out	dx, ax		; restore Bit Mask register

	pop	es
	pop	di
	pop	si
	pop	bp
#endasm
}

/*
* Routine to draw a vertical line.
* Called from C:
*	ega_drawvline(psd, x, y1, y2, color);
*
*	works in the following EGA and VGA modes:
*	200 line 16 colors modes
*	350 line modes
*	640x480 16 color
*/
/* Draw a vertical line from x,y1 to x,y2 including final point*/
void
ega_drawvertline(PSD psd, int x,int y1, int y2, int color)
{
#asm
	push	bp		; setup stack frame and preserve registers
	mov	bp, sp
	push	ds

	dec	[bp+10]		; dec y2 - don't draw final point
	; configure the graphics controller

	mov	dx, #$03ce	; DX := Graphics Controller port address

	mov	al, #3		; set data rotate register
	lea	bx, _mode_table
	add	bx, _gr_mode
	mov	ah, [bx]
	out	dx, ax

	mov 	ah, [bp+12]	; color pixel value
	xor	al, al		; Set/Reset register number (0)
	out	dx, ax

	mov	ax, #$0f01	; AH := bit plane mask for Enable Set/Reset
	out	dx, ax		; AL := Enable Set/Reset register number

	; prepare to draw vertical line

	mov	ax, [bp+8]	; AX := y1
	mov	cx, [bp+10]	; BX := y2
	;;mov	cx, bx
	sub	cx, ax		; CX := dy
	;;jge	L311		; jump if dy >= 0
	;;neg	cx		; force dy >= 0
	;;mov	ax, bx		; AX := y2

L311:	inc	cx		; CX := number of pixels to draw
	mov	bx, [bp+6]	; BX := x
	push	cx		; save register

	; compute pixel address
	push	dx
	mov	dx, #BYTESPERLINE ; AX := [row * BYTESPERLINE]
	mul	dx
	mov 	cl, bl		; save low order column bits
	shr	bx, #1		; BX := [col / 8]
	shr	bx, #1
	shr	bx, #1
	add	bx, ax		; BX := [row * BYTESPERLINE] + [col / 8]
	and	cl, #$07	; CL := [col % 8]
	xor	cl, #$07	; CL := 7 - [col % 8]
	mov 	ah, #$01	; AH := 1 << [7 - [col % 8]]	[mask]
	mov	dx, #SCREENSEG	; DS := EGA buffer segment address
	mov	ds, dx
	pop	dx
				; AH := bit mask
				; DS:BX -> video buffer
				; CL := number bits to shift left

	; set up Graphics controller

	shl	ah, cl		; AH := bit mask in proper position
	mov 	al, #$08	; AL := Bit Mask register number
	out	dx, ax

	pop	cx		; restore register

	; draw the line

	mov	dx, #BYTESPERLINE ; increment for video buffer
L1111:	or	[bx], al	; set pixel
	add	bx, dx		; increment to next line
	loop	L1111

	; restore default Graphics Controller state and return to caller
	;;xor	ax, ax		; AH := 0, AL := 0
	;;out	dx, ax		; restore Set/Reset register
	;;inc	ax		; AH := 0, AL := 1
	;;out	dx, ax		; restore Enable Set/Reset register
	;;mov	ax, #$0ff08	; AH := 0xff, AL := 0
	;;out	dx, ax		; restore Bit Mask register

	pop	ds
	pop	bp
#endasm
}

/*
* Routine to set an individual pixel value.
* Called from C like:
*	ega_drawpixel(psd, x, y, color);
*/
void
ega_drawpixel(PSD psd, int x, int y, int color)
{
#asm
	push	bp
	mov	bp, sp

	mov	dx, #$03ce	; graphics controller port address
	mov	al, #3		; set data rotate register
	lea	bx, _mode_table
	add	bx, _gr_mode
	mov	ah, [bx]
	out	dx, ax

	mov	cx, [bp+6]	; ECX := x
	mov	ax, [bp+8]	; EAX := y

	mov	dx, #BYTESPERLINE ; AX := [y * BYTESPERLINE]
	mul	dx

	mov	bx, cx		; BX := [x / 8]
	shr	bx, #1
	shr	bx, #1
	shr	bx, #1

	add	bx, ax		; BX := [y * BYTESPERLINE] + [x / 8]

	and	cl, #$07	; CL := [x % 8]
	xor	cl, #$07	; CL := 7 - [x % 8]
	mov 	ch, #$01	; CH := 1 << [7 - [x % 8]]	[mask]
	shl	ch, cl

	mov	dx, #$03ce	; graphics controller port address

	;;required for old code
	mov	ax, #$0205	; select write mode 2
	out	dx, ax		; [load value 2 into mode register 5]

	; new code
	;;xor	ax,ax		; set color register 0
	;;mov	ah,[bp+10]	; color pixel value
	;;out	dx,ax

	; original code
	mov 	al, #$08	; set the bit mask register
	mov 	ah, ch		; [load bit mask into register 8]
	out	dx, ax

	push	ds
	mov	ax, #SCREENSEG	; DS := EGA buffer segment address
	mov	ds, ax

	; new code
	;;or	[bx],al		; quick rmw to set pixel

	;;the following fails under ELKS without cli/sti
	;;using ES works though.  Code changed to use single
	;;rmw above rather than write mode 2, but the
	;;reason for this failure is still unknown...
	;;cli
	mov 	al, [bx]	; dummy read to latch bit planes
	mov	al, [bp+10]	; pixel value
	mov 	[bx], al	; write pixel back to bit planes
	;;sti

	pop	ds		; restore registers and return

	mov	ax, #$0005	; restore default write mode 0
	out	dx, ax		; [load value 0 into mode register 5]

	;;mov	ax, #$0ff08	; restore default bit mask
	;;out	dx, ax		; [load value ff into register 8]

	pop	bp
#endasm
}

/*
* Routine to read the value of an individual pixel.
* Called from C like:
* 	color = ega_readpixel(psd, x, y);
*/
PIXELVAL
ega_readpixel(PSD psd, int x, int y)
{
#asm
	push	bp
	mov	bp, sp
	push	si
	push	ds

	mov	ax, [bp+8]	; EAX := y
	mov	bx, [bp+6]	; EBX := x
	mov	dx, #BYTESPERLINE ; AX := [y * BYTESPERLINE]
	mul	dx

	mov 	cl, bl		; save low order column bits
	shr	bx, #1		; BX := [x / 8]
	shr	bx, #1
	shr	bx, #1

	add	bx, ax		; BX := [y * BYTESPERLINE] + [x / 8]

	and	cl, #$07	; CL := [x % 8]
	xor 	cl, #$07	; CL := 7 - [x % 8]

	mov	dx, #SCREENSEG	; DS := EGA buffer segment address
	mov	ds, dx

	mov 	ch, #$01	; CH := 1 << [7 - [col % 8]]  [mask]
	shl	ch, cl		; CH := bit mask in proper position

	mov	si, bx		; DS:SI -> region buffer byte
	xor	bl, bl		; BL is used to accumulate the pixel value

	mov	dx, #$03ce	; DX := Graphics Controller port
	mov	ax, #$0304	; AH := initial bit plane number
				; AL := Read Map Select register number

L112:	out	dx, ax		; select bit plane
	mov 	bh, [si]	; BH := byte from current bit plane
	and	bh, ch		; mask one bit
	neg	bh		; bit 7 of BH := 1 if masked bit = 1
				; bit 7 of BH := 0 if masked bit = 0
	rol	bx, #1		; bit 0 of BL := next bit from pixel value
	dec	ah		; AH := next bit plane number
	jge	L112

	xor	ax, ax		; AL := pixel value
	mov 	al, bl

	pop	ds
	pop	si
	pop	bp	
#endasm
}

void
ega_blit(PSD dstpsd, COORD dstx, COORD dsty, COORD w, COORD h,
	PSD srcpsd, COORD srcx, COORD srcy, int op)
{
#if HAVEBLIT
	BOOL	srcvga, dstvga;

	/* decide which blit algorithm to use*/
	srcvga = srcpsd->flags & PSF_SCREEN;
	dstvga = dstpsd->flags & PSF_SCREEN;

	if(srcvga) {
		if(dstvga)
			vga_to_vga_blit(dstpsd, dstx, dsty, w, h,
				srcpsd, srcx, srcy, op);
		else
			vga_to_mempl4_blit(dstpsd, dstx, dsty, w, h,
				srcpsd, srcx, srcy, op);
	} else {
		if(dstvga)
			mempl4_to_vga_blit(dstpsd, dstx, dsty, w, h,
				srcpsd, srcx, srcy, op);
		else
			mempl4_to_mempl4_blit(dstpsd, dstx, dsty, w, h,
				srcpsd, srcx, srcy, op);
	}
#endif /* HAVEBLIT*/
}
