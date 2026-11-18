/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * X11 native dialogs (credentials and certificate verification) using plain Xlib
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <X11/Xlib.h>
#include <X11/Xatom.h>
#include <X11/Xutil.h>
#include <X11/keysym.h>

#include <winpr/assert.h>
#include <winpr/environment.h>
#include <winpr/string.h>

#include <freerdp/settings.h>
#include <freerdp/log.h>
#include <freerdp/crypto/certificate.h>

#include "xfreerdp.h"
#include "xf_dialogs.h"

#define TAG CLIENT_TAG("x11")

#define DLG_MARGIN 16
#define DLG_FIELD_BUF 512
#define DLG_USER_BUF 256
#define DLG_TEXT_BUF 1024
#define DLG_BUTTON_H 30
#define DLG_FIELD_H 24

#define DLG_AUTH_WIDTH 460
#define DLG_CERT_WIDTH 560
#define DLG_CERT_LABEL_W 140

/* Field indices of the authentication dialog, buttons come after them */
#define AUTH_FIELD_USER 0
#define AUTH_FIELD_PASS 1
#define AUTH_FIELD_DOMAIN 2
#define AUTH_BUTTON_CONNECT 3
#define AUTH_BUTTON_CANCEL 4
#define AUTH_ITEMS 5

typedef struct
{
	const char* label;
	int value;
	int x;
	int y;
	int w;
	int h;
} xfDlgButton;

typedef struct
{
	char** lines;
	size_t count;
	size_t cap;
} xfDlgLines;

typedef struct
{
	Display* display;
	int screen;
	Window window;
	Pixmap buffer;
	GC gc;
	XFontSet fs;
	int ascent;
	int line_height;
	int width;
	int height;
	Atom wm_delete;
	unsigned long c_bg;
	unsigned long c_fg;
	unsigned long c_field;
	unsigned long c_border;
	unsigned long c_focus;
	unsigned long c_button;
	unsigned long c_hover;
	unsigned long c_warn;
	BOOL dirty;
} xfDlg;

/* Overwrite a buffer in a way the compiler cannot drop, used for password data */
static void dlg_wipe(void* data, size_t size)
{
	volatile unsigned char* p = (volatile unsigned char*)data;

	while (size--)
		*p++ = 0;
}

static unsigned long dlg_alloc_color(Display* display, const char* rgb, unsigned long fallback)
{
	XColor color = WINPR_C_ARRAY_INIT;
	const Colormap cmap = DefaultColormap(display, XDefaultScreen(display));

	if (!XParseColor(display, cmap, rgb, &color))
		return fallback;
	if (!XAllocColor(display, cmap, &color))
		return fallback;
	return color.pixel;
}

static XFontSet dlg_load_fontset(Display* display)
{
	/* Fall back to "fixed" if the preferred font is not installed on the server */
	static const char* const names[] = { "-*-*-medium-r-normal--14-*-*-*-*-*-*-*",
	                                     "-*-fixed-medium-r-*-*-13-*-*-*-*-*-*-*", "fixed" };

	for (size_t i = 0; i < ARRAYSIZE(names); i++)
	{
		char** missing = nullptr;
		int count = 0;
		char* def = nullptr;
		XFontSet fs = XCreateFontSet(display, names[i], &missing, &count, &def);

		if (missing)
			XFreeStringList(missing);

		if (fs)
			return fs;
	}

	return nullptr;
}

static int dlg_text_width(const XFontSet fs, const char* text, size_t len)
{
	if (len == 0)
		return 0;
	return XmbTextEscapement(fs, text, (int)len);
}

/* Length in bytes of the UTF-8 character starting at p, never past end */
static size_t dlg_utf8_len(const char* p, size_t remaining)
{
	unsigned char c = 0;
	size_t n = 1;

	if (remaining == 0)
		return 0;
	/* remaining is checked above, the analyzer cannot relate it to p */
	// NOLINTNEXTLINE(clang-analyzer-security.ArrayBound)
	c = (unsigned char)*p;

	if (c >= 0xF0)
		n = 4;
	else if (c >= 0xE0)
		n = 3;
	else if (c >= 0xC0)
		n = 2;

	if (remaining < n)
		n = remaining;
	return n;
}

static BOOL dlg_lines_add(xfDlgLines* l, const char* start, size_t len)
{
	if (l->count == l->cap)
	{
		const size_t ncap = l->cap ? l->cap * 2 : 8;
		char** tmp = (char**)realloc((void*)l->lines, ncap * sizeof(char*));

		if (!tmp)
			return FALSE;
		l->lines = tmp;
		l->cap = ncap;
	}

	char* copy = malloc(len + 1);
	if (!copy)
		return FALSE;
	memcpy(copy, start, len);
	copy[len] = '\0';
	l->lines[l->count++] = copy;
	return TRUE;
}

static void dlg_lines_free(xfDlgLines* l)
{
	for (size_t i = 0; i < l->count; i++)
		free(l->lines[i]);
	free((void*)l->lines);
	l->lines = nullptr;
	l->count = 0;
	l->cap = 0;
}

/* Split text into lines that fit maxw pixels. Newlines start a new line, long words are
 * broken at a space when possible and at a character boundary otherwise.
 */
static BOOL dlg_wrap(const XFontSet fs, const char* text, int maxw, xfDlgLines* out)
{
	const char* p = nullptr;

	if (!text)
		text = "";
	p = text;

	while (1)
	{
		const char* nl = strchr(p, '\n');
		const char* para_end = nl ? nl : p + strlen(p);
		const char* line = p;
		const char* cur = p;
		const char* last_space = nullptr;

		if (line == para_end)
		{
			if (!dlg_lines_add(out, line, 0))
				return FALSE;
		}

		while (cur < para_end)
		{
			const char* next = cur + dlg_utf8_len(cur, (size_t)(para_end - cur));

			/* cur < para_end is the loop condition, the analyzer cannot relate it to cur */
			// NOLINTNEXTLINE(clang-analyzer-security.ArrayBound)
			if (*cur == ' ')
				last_space = cur;

			if (dlg_text_width(fs, line, (size_t)(next - line)) > maxw)
			{
				if (last_space && (last_space > line))
				{
					if (!dlg_lines_add(out, line, (size_t)(last_space - line)))
						return FALSE;
					line = last_space + 1;
				}
				else if (cur > line)
				{
					if (!dlg_lines_add(out, line, (size_t)(cur - line)))
						return FALSE;
					line = cur;
				}
				else
				{
					/* a single character wider than the line */
					if (!dlg_lines_add(out, cur, (size_t)(next - cur)))
						return FALSE;
					line = next;
				}

				cur = line;
				last_space = nullptr;
				continue;
			}

			cur = next;
		}

		if (line < para_end)
		{
			if (!dlg_lines_add(out, line, (size_t)(para_end - line)))
				return FALSE;
		}

		if (!nl)
			break;
		p = nl + 1;
	}

	return TRUE;
}

static void dlg_text(const xfDlg* st, Drawable d, int x, int top, const char* text, size_t len)
{
	if (len == 0)
		return;
	XmbDrawString(st->display, d, st->fs, st->gc, x, top + st->ascent, text, (int)len);
}

static void dlg_blit(xfDlg* st)
{
	XCopyArea(st->display, st->buffer, st->window, st->gc, 0, 0, (unsigned int)st->width,
	          (unsigned int)st->height, 0, 0);
	XFlush(st->display);
	st->dirty = FALSE;
}

static void dlg_fill(const xfDlg* st, unsigned long color, int x, int y, int w, int h)
{
	XSetForeground(st->display, st->gc, color);
	XFillRectangle(st->display, st->buffer, st->gc, x, y, (unsigned int)w, (unsigned int)h);
}

static void dlg_frame(const xfDlg* st, unsigned long color, int x, int y, int w, int h)
{
	XSetForeground(st->display, st->gc, color);
	XDrawRectangle(st->display, st->buffer, st->gc, x, y, (unsigned int)(w - 1),
	               (unsigned int)(h - 1));
}

static void dlg_draw_button(const xfDlg* st, const xfDlgButton* b, BOOL hover, BOOL focus)
{
	const unsigned long bg = hover ? st->c_hover : st->c_button;
	const size_t len = strlen(b->label);
	const int tw = dlg_text_width(st->fs, b->label, len);

	dlg_fill(st, bg, b->x, b->y, b->w, b->h);
	dlg_frame(st, st->c_border, b->x, b->y, b->w, b->h);
	if (focus)
		dlg_frame(st, st->c_focus, b->x + 2, b->y + 2, b->w - 4, b->h - 4);

	XSetForeground(st->display, st->gc, st->c_fg);
	dlg_text(st, st->buffer, b->x + (b->w - tw) / 2, b->y + (b->h - st->line_height) / 2, b->label,
	         len);
}

/* Load the font and the colors, this is all that is needed to measure the layout */
static BOOL dlg_init(xfDlg* st, Display* display)
{
	WINPR_ASSERT(st);
	WINPR_ASSERT(display);

	memset(st, 0, sizeof(*st));
	st->display = display;
	st->screen = XDefaultScreen(display);

	st->fs = dlg_load_fontset(display);
	if (!st->fs)
		return FALSE;

	const XFontSetExtents* ext = XExtentsOfFontSet(st->fs);
	st->ascent = -ext->max_logical_extent.y;
	st->line_height = ext->max_logical_extent.height;

	st->c_bg = dlg_alloc_color(display, "RGB:F0/F0/F0", WhitePixel(display, st->screen));
	st->c_fg = dlg_alloc_color(display, "RGB:20/20/20", BlackPixel(display, st->screen));
	st->c_field = dlg_alloc_color(display, "RGB:FF/FF/FF", WhitePixel(display, st->screen));
	st->c_border = dlg_alloc_color(display, "RGB:9A/9A/9A", BlackPixel(display, st->screen));
	st->c_focus = dlg_alloc_color(display, "RGB:31/6C/A9", BlackPixel(display, st->screen));
	st->c_button = dlg_alloc_color(display, "RGB:DD/DD/DD", WhitePixel(display, st->screen));
	st->c_hover = dlg_alloc_color(display, "RGB:C4/D6/EA", WhitePixel(display, st->screen));
	st->c_warn = dlg_alloc_color(display, "RGB:B0/30/20", BlackPixel(display, st->screen));
	return TRUE;
}

/* Create the window, its pixmap and its properties, with the final size */
static BOOL dlg_create_window(xfDlg* st, const char* title, int width, int height)
{
	XSetWindowAttributes attrs = WINPR_C_ARRAY_INIT;
	XSizeHints hints = WINPR_C_ARRAY_INIT;
	Atom type_dialog = None;
	Atom net_wm_type = None;
	Atom net_wm_name = None;
	Atom utf8 = None;
	Display* display = st->display;
	const Window root = RootWindow(display, st->screen);

	WINPR_ASSERT(st);
	WINPR_ASSERT(st->display);

	st->width = width;
	st->height = height;

	attrs.background_pixel = st->c_bg;
	attrs.event_mask = ExposureMask | KeyPressMask | ButtonPressMask | ButtonReleaseMask |
	                   PointerMotionMask | StructureNotifyMask;

	const int x = (XDisplayWidth(display, st->screen) - width) / 2;
	const int y = (XDisplayHeight(display, st->screen) - height) / 2;
	st->window = XCreateWindow(display, root, x > 0 ? x : 0, y > 0 ? y : 0, (unsigned int)width,
	                           (unsigned int)height, 1, CopyFromParent, InputOutput, CopyFromParent,
	                           CWBackPixel | CWEventMask, &attrs);
	if (!st->window)
		return FALSE;

	st->buffer = XCreatePixmap(display, st->window, (unsigned int)width, (unsigned int)height,
	                           (unsigned int)DefaultDepth(display, st->screen));
	st->gc = XCreateGC(display, st->window, 0, nullptr);
	if (!st->buffer || !st->gc)
		return FALSE;

	/* window properties: title, dialog type, fixed size and the close button */
	XStoreName(display, st->window, title ? title : "FreeRDP");
	utf8 = XInternAtom(display, "UTF8_STRING", False);
	net_wm_name = XInternAtom(display, "_NET_WM_NAME", False);
	if (utf8 != None && net_wm_name != None)
		XChangeProperty(display, st->window, net_wm_name, utf8, 8, PropModeReplace,
		                (const unsigned char*)(title ? title : "FreeRDP"),
		                (int)strlen(title ? title : "FreeRDP"));

	net_wm_type = XInternAtom(display, "_NET_WM_WINDOW_TYPE", False);
	type_dialog = XInternAtom(display, "_NET_WM_WINDOW_TYPE_DIALOG", False);
	if (net_wm_type != None && type_dialog != None)
		XChangeProperty(display, st->window, net_wm_type, XA_ATOM, 32, PropModeReplace,
		                (const unsigned char*)&type_dialog, 1);

	st->wm_delete = XInternAtom(display, "WM_DELETE_WINDOW", False);
	XSetWMProtocols(display, st->window, &st->wm_delete, 1);

	hints.flags = PMinSize | PMaxSize;
	hints.min_width = hints.max_width = width;
	hints.min_height = hints.max_height = height;
	XSetWMNormalHints(display, st->window, &hints);

	XMapRaised(display, st->window);
	st->dirty = TRUE;
	return TRUE;
}

/* Give the keyboard focus to the dialog once the server reports it mapped, an earlier
 * request is rejected with BadMatch because the window is not viewable yet.
 */
static void dlg_on_mapped(xfDlg* st)
{
	XSetInputFocus(st->display, st->window, RevertToParent, CurrentTime);
	st->dirty = TRUE;
}

static void dlg_close(xfDlg* st)
{
	if (!st || !st->display)
		return;

	if (st->gc)
		XFreeGC(st->display, st->gc);
	if (st->buffer)
		XFreePixmap(st->display, st->buffer);
	if (st->window)
		XDestroyWindow(st->display, st->window);
	if (st->fs)
		XFreeFontSet(st->display, st->fs);
	XFlush(st->display);
	memset(st, 0, sizeof(*st));
}

static BOOL dlg_inside(int x, int y, int rx, int ry, int rw, int rh)
{
	return (x >= rx) && (x < rx + rw) && (y >= ry) && (y < ry + rh);
}

/* Remove the last UTF-8 character of a NUL terminated buffer */
static void dlg_pop_char(char* buf)
{
	size_t len = strlen(buf);

	if (len == 0)
		return;

	do
	{
		len--;
	} while ((len > 0) && ((((unsigned int)(unsigned char)buf[len]) & 0xC0U) == 0x80U));

	buf[len] = '\0';
}

static BOOL dlg_push_text(char* buf, size_t cap, const char* text, unsigned int n)
{
	const size_t len = strlen(buf);

	if (len + n + 1 > cap)
		return FALSE;
	memcpy(buf + len, text, n);
	buf[len + n] = '\0';
	return TRUE;
}

static void dlg_draw_field(const xfDlg* st, int x, int y, int w, int h, const char* text, BOOL mask,
                           BOOL focus, const char* label)
{
	char masked[DLG_FIELD_BUF] = WINPR_C_ARRAY_INIT;
	const char* shown = text;
	size_t shown_len = strlen(text);

	XSetForeground(st->display, st->gc, st->c_fg);
	dlg_text(st, st->buffer, DLG_MARGIN, y + (h - st->line_height) / 2, label, strlen(label));

	if (mask)
	{
		size_t n = 0;
		for (const char* p = text; *p && (n + 1 < sizeof(masked));)
		{
			p += dlg_utf8_len(p, strlen(p));
			masked[n++] = '*';
		}
		masked[n] = '\0';
		shown = masked;
		shown_len = n;
	}

	dlg_fill(st, st->c_field, x, y, w, h);
	dlg_frame(st, focus ? st->c_focus : st->c_border, x, y, w, h);

	/* clip the text to the field so long input does not paint over the frame */
	XRectangle clip = { (short)(x + 1), (short)(y + 1), (unsigned short)(w - 2),
	                    (unsigned short)(h - 2) };
	XSetClipRectangles(st->display, st->gc, 0, 0, &clip, 1, Unsorted);
	XSetForeground(st->display, st->gc, st->c_fg);
	dlg_text(st, st->buffer, x + 6, y + (h - st->line_height) / 2, shown, shown_len);
	if (focus)
	{
		const int cw = dlg_text_width(st->fs, shown, shown_len);
		dlg_fill(st, st->c_fg, x + 6 + cw, y + 4, 1, h - 8);
	}
	XSetClipMask(st->display, st->gc, None);
}

/* ---------- authentication dialog ---------- */

typedef struct
{
	char user[DLG_USER_BUF];
	char pass[DLG_FIELD_BUF];
	char domain[DLG_USER_BUF];
} xfAuthInput;

static void auth_rects(xfDlgButton* buttons, int* fx, int* fy, int* fw, int* fh)
{
	const int top = 52;
	const int step = 36;

	for (int i = 0; i < 3; i++)
	{
		fx[i] = 130;
		fy[i] = top + i * step;
		fw[i] = DLG_AUTH_WIDTH - 130 - DLG_MARGIN;
		fh[i] = DLG_FIELD_H;
	}

	buttons[0].label = "Conectar";
	buttons[0].value = 1;
	buttons[0].x = DLG_AUTH_WIDTH - DLG_MARGIN - 230;
	buttons[0].w = 100;
	buttons[1].label = "Cancelar";
	buttons[1].value = 0;
	buttons[1].x = DLG_AUTH_WIDTH - DLG_MARGIN - 110;
	buttons[1].w = 100;
	for (int i = 0; i < 2; i++)
	{
		buttons[i].y = 176;
		buttons[i].h = DLG_BUTTON_H;
	}
}

static void auth_draw(const xfDlg* st, const xfAuthInput* in, const char* title, int focus,
                      int hover)
{
	int fx[3] = { 0 };
	int fy[3] = { 0 };
	int fw[3] = { 0 };
	int fh[3] = { 0 };
	xfDlgButton buttons[2] = { 0 };

	auth_rects(buttons, fx, fy, fw, fh);

	dlg_fill(st, st->c_bg, 0, 0, st->width, st->height);
	XSetForeground(st->display, st->gc, st->c_fg);
	dlg_text(st, st->buffer, DLG_MARGIN, 14, title, strlen(title));

	dlg_draw_field(st, fx[0], fy[0], fw[0], fh[0], in->user, FALSE, focus == AUTH_FIELD_USER,
	               "Usuario:");
	dlg_draw_field(st, fx[1], fy[1], fw[1], fh[1], in->pass, TRUE, focus == AUTH_FIELD_PASS,
	               "Senha:");
	dlg_draw_field(st, fx[2], fy[2], fw[2], fh[2], in->domain, FALSE, focus == AUTH_FIELD_DOMAIN,
	               "Dominio:");

	for (int i = 0; i < 2; i++)
		dlg_draw_button(st, &buttons[i], hover == i, focus == (AUTH_BUTTON_CONNECT + i));
}

static int auth_hit_button(int x, int y)
{
	int fx[3] = { 0 };
	int fy[3] = { 0 };
	int fw[3] = { 0 };
	int fh[3] = { 0 };
	xfDlgButton buttons[2] = { 0 };

	auth_rects(buttons, fx, fy, fw, fh);
	for (int i = 0; i < 2; i++)
	{
		if (dlg_inside(x, y, buttons[i].x, buttons[i].y, buttons[i].w, buttons[i].h))
			return i;
	}
	return -1;
}

static int auth_hit_field(int x, int y)
{
	int fx[3] = { 0 };
	int fy[3] = { 0 };
	int fw[3] = { 0 };
	int fh[3] = { 0 };
	xfDlgButton buttons[2] = { 0 };

	auth_rects(buttons, fx, fy, fw, fh);
	for (int i = 0; i < 3; i++)
	{
		if (dlg_inside(x, y, fx[i], fy[i], fw[i], fh[i]))
			return i;
	}
	return -1;
}

int xf_xlib_authenticate_dialog(Display* display, const char* title, const char* username,
                                const char* domain, char** out_username, char** out_password,
                                char** out_domain)
{
	xfDlg st = WINPR_C_ARRAY_INIT;
	xfAuthInput in = WINPR_C_ARRAY_INIT;
	int focus = AUTH_FIELD_PASS;
	int hover = -1;
	int pressed = -1;
	int result = 0;
	BOOL done = FALSE;
	int rc = 0;

	if (!display || !out_username || !out_password || !out_domain)
		return XF_DIALOG_UNAVAILABLE;

	if (username)
		(void)strncpy(in.user, username, sizeof(in.user) - 1);
	if (domain)
		(void)strncpy(in.domain, domain, sizeof(in.domain) - 1);
	if (in.user[0] == '\0')
		focus = AUTH_FIELD_USER;

	if (!dlg_init(&st, display) || !dlg_create_window(&st, title, DLG_AUTH_WIDTH, 224))
	{
		dlg_close(&st);
		dlg_wipe(&in, sizeof(in));
		return XF_DIALOG_UNAVAILABLE;
	}

	while (!done)
	{
		XEvent ev = WINPR_C_ARRAY_INIT;

		XNextEvent(display, &ev);

		switch (ev.type)
		{
			case Expose:
				if (ev.xexpose.count == 0)
					st.dirty = TRUE;
				break;

			case MapNotify:
				/* drawing does not depend only on Expose, the map is enough to repaint */
				dlg_on_mapped(&st);
				break;

			case ClientMessage:
				if ((Atom)ev.xclient.data.l[0] == st.wm_delete)
				{
					result = 0;
					done = TRUE;
				}
				break;

			case KeyPress:
			{
				char text[32] = WINPR_C_ARRAY_INIT;
				KeySym ks = NoSymbol;
				const int n = XLookupString(&ev.xkey, text, sizeof(text) - 1, &ks, nullptr);
				char* target = nullptr;
				size_t target_cap = 0;

				if (ks == XK_Escape)
				{
					result = 0;
					done = TRUE;
					break;
				}

				if ((ks == XK_Tab) || (ks == XK_ISO_Left_Tab))
				{
					const BOOL back =
					    (ks == XK_ISO_Left_Tab) || (ev.xkey.state & (unsigned int)ShiftMask);
					focus = (focus + (back ? AUTH_ITEMS - 1 : 1)) % AUTH_ITEMS;
					st.dirty = TRUE;
					break;
				}

				if ((ks == XK_Return) || (ks == XK_KP_Enter))
				{
					if (in.user[0] != '\0')
					{
						result = 1;
						done = TRUE;
					}
					else
					{
						focus = AUTH_FIELD_USER;
						st.dirty = TRUE;
					}
					break;
				}

				if (focus == AUTH_BUTTON_CANCEL)
				{
					if ((ks == XK_space) || (ks == XK_KP_Space))
					{
						result = 0;
						done = TRUE;
					}
					break;
				}
				if (focus == AUTH_BUTTON_CONNECT)
				{
					if ((ks == XK_space) || (ks == XK_KP_Space))
					{
						if (in.user[0] != '\0')
						{
							result = 1;
							done = TRUE;
						}
					}
					break;
				}

				if (focus == AUTH_FIELD_USER)
				{
					target = in.user;
					target_cap = sizeof(in.user);
				}
				else if (focus == AUTH_FIELD_PASS)
				{
					target = in.pass;
					target_cap = sizeof(in.pass);
				}
				else
				{
					target = in.domain;
					target_cap = sizeof(in.domain);
				}

				if ((ks == XK_BackSpace) || (ks == XK_Delete))
				{
					dlg_pop_char(target);
					st.dirty = TRUE;
				}
				else if ((n > 0) && ((unsigned char)text[0] >= 0x20) && (text[0] != 0x7f))
				{
					if (dlg_push_text(target, target_cap, text, (unsigned int)n))
						st.dirty = TRUE;
				}

				/* the keystroke may be part of the password */
				dlg_wipe(text, sizeof(text));
				break;
			}

			case ButtonPress:
				if (ev.xbutton.button != Button1)
					break;
				{
					const int field = auth_hit_field(ev.xbutton.x, ev.xbutton.y);
					const int button = auth_hit_button(ev.xbutton.x, ev.xbutton.y);

					if (field >= 0)
						focus = field;
					else if (button >= 0)
					{
						pressed = button;
						focus = AUTH_BUTTON_CONNECT + button;
					}
					st.dirty = TRUE;
				}
				break;

			case ButtonRelease:
				if (ev.xbutton.button != Button1)
					break;
				{
					const int button = auth_hit_button(ev.xbutton.x, ev.xbutton.y);

					if ((button >= 0) && (button == pressed))
					{
						if ((button == 0) && (in.user[0] == '\0'))
							focus = AUTH_FIELD_USER;
						else
						{
							result = (button == 0) ? 1 : 0;
							done = TRUE;
						}
					}
					pressed = -1;
					st.dirty = TRUE;
				}
				break;

			case MotionNotify:
			{
				const int h = auth_hit_button(ev.xmotion.x, ev.xmotion.y);
				if (h != hover)
				{
					hover = h;
					st.dirty = TRUE;
				}
				break;
			}

			default:
				break;
		}

		if (st.dirty && !done)
		{
			auth_draw(&st, &in, title, focus, hover);
			dlg_blit(&st);
		}
	}

	if (result == 1)
	{
		*out_username = _strdup(in.user);
		*out_password = _strdup(in.pass);
		*out_domain = _strdup(in.domain);

		if (!*out_username || !*out_password || !*out_domain)
		{
			free(*out_username);
			free(*out_password);
			free(*out_domain);
			*out_username = nullptr;
			*out_password = nullptr;
			*out_domain = nullptr;
			rc = XF_DIALOG_UNAVAILABLE;
		}
		else
			rc = 1;
	}

	dlg_wipe(&in, sizeof(in));
	dlg_close(&st);
	return rc;
}

/* ---------- certificate dialog ---------- */

static void cert_draw(const xfDlg* st, const xfDlgLines* heading, const xfDlgLines* warning,
                      const xfDlgLines* labels, const xfDlgLines* values, const size_t* rows,
                      size_t field_count, const xfDlgButton* buttons, int focus, int hover)
{
	const int lh = st->line_height;
	int y = DLG_MARGIN;

	dlg_fill(st, st->c_bg, 0, 0, st->width, st->height);

	XSetForeground(st->display, st->gc, st->c_fg);
	for (size_t i = 0; i < heading->count; i++)
	{
		dlg_text(st, st->buffer, DLG_MARGIN, y, heading->lines[i], strlen(heading->lines[i]));
		y += lh;
	}
	y += 8;

	XSetForeground(st->display, st->gc, st->c_warn);
	for (size_t i = 0; i < warning->count; i++)
	{
		dlg_text(st, st->buffer, DLG_MARGIN, y, warning->lines[i], strlen(warning->lines[i]));
		y += lh;
	}
	y += 12;

	size_t vi = 0;
	for (size_t f = 0; f < field_count; f++)
	{
		const size_t nrows = rows[f];

		XSetForeground(st->display, st->gc, st->c_fg);
		dlg_text(st, st->buffer, DLG_MARGIN, y, labels->lines[f], strlen(labels->lines[f]));

		for (size_t r = 0; r < nrows; r++, vi++)
		{
			dlg_text(st, st->buffer, DLG_MARGIN + DLG_CERT_LABEL_W, y + (int)r * lh,
			         values->lines[vi], strlen(values->lines[vi]));
		}
		y += (int)nrows * lh + 6;
	}

	for (int i = 0; i < 3; i++)
		dlg_draw_button(st, &buttons[i], hover == i, focus == i);
}

/* Wrap the labels and values and compute the height of the window */
static int cert_layout(const xfDlg* st, const xfDialogField* fields, size_t count,
                       const char* heading, const char* warning, xfDlgLines* hl, xfDlgLines* wl,
                       xfDlgLines* ll, xfDlgLines* vl, size_t* rows, int* out_height)
{
	const int inner = DLG_CERT_WIDTH - 2 * DLG_MARGIN;
	const int value_w = inner - DLG_CERT_LABEL_W;
	int y = DLG_MARGIN;

	if (!dlg_wrap(st->fs, heading, inner, hl))
		return -1;
	y += (int)hl->count * st->line_height + 8;

	if (!dlg_wrap(st->fs, warning, inner, wl))
		return -1;
	y += (int)wl->count * st->line_height + 12;

	for (size_t f = 0; f < count; f++)
	{
		xfDlgLines one = WINPR_C_ARRAY_INIT;

		const char* label = fields[f].label ? fields[f].label : "";

		if (!dlg_lines_add(ll, label, strlen(label)) ||
		    !dlg_wrap(st->fs, fields[f].value ? fields[f].value : "", value_w, &one))
		{
			dlg_lines_free(&one);
			return -1;
		}

		/* the label takes the first row, the value the rows of its wrapped text */
		rows[f] = one.count ? one.count : 1;
		for (size_t i = 0; i < one.count; i++)
		{
			if (!dlg_lines_add(vl, one.lines[i], strlen(one.lines[i])))
			{
				dlg_lines_free(&one);
				return -1;
			}
		}
		dlg_lines_free(&one);
		y += (int)rows[f] * st->line_height + 6;
	}

	y += 12;
	*out_height = y + DLG_BUTTON_H + DLG_MARGIN;
	return 0;
}

int xf_xlib_certificate_dialog(Display* display, const char* title, const char* heading,
                               const char* warning, const xfDialogField* fields, size_t count)
{
	xfDlg st = WINPR_C_ARRAY_INIT;
	xfDlgLines hl = WINPR_C_ARRAY_INIT;
	xfDlgLines wl = WINPR_C_ARRAY_INIT;
	xfDlgLines ll = WINPR_C_ARRAY_INIT;
	xfDlgLines vl = WINPR_C_ARRAY_INIT;
	size_t* rows = nullptr;
	int height = 0;
	int result = 0;
	int focus = 2; /* "Recusar" is the default, a careless Enter must not trust the server */
	int hover = -1;
	int pressed = -1;
	BOOL done = FALSE;
	int rc = XF_DIALOG_UNAVAILABLE;
	xfDlgButton buttons[3] = {
		{ "Aceitar Sempre", 1, 0, 0, 160, DLG_BUTTON_H },
		{ "Aceitar Uma Vez", 2, 0, 0, 160, DLG_BUTTON_H },
		{ "Recusar", 0, 0, 0, 160, DLG_BUTTON_H },
	};

	if (!display || !fields || (count == 0))
		return XF_DIALOG_UNAVAILABLE;

	rows = calloc(count, sizeof(size_t));
	if (!rows)
		return XF_DIALOG_UNAVAILABLE;

	/* measure the content first, the window is created with its final height */
	if (!dlg_init(&st, display))
		goto out;

	if (cert_layout(&st, fields, count, heading ? heading : "", warning ? warning : "", &hl, &wl,
	                &ll, &vl, rows, &height) < 0)
		goto out;

	if (!dlg_create_window(&st, title, DLG_CERT_WIDTH, height))
		goto out;

	{
		XSizeHints hints = WINPR_C_ARRAY_INIT;
		hints.flags = PMinSize | PMaxSize;
		hints.min_width = hints.max_width = DLG_CERT_WIDTH;
		hints.min_height = hints.max_height = height;
		XSetWMNormalHints(display, st.window, &hints);
	}

	for (int i = 0; i < 3; i++)
	{
		buttons[i].x = DLG_CERT_WIDTH - DLG_MARGIN - (3 - i) * 170 + 10;
		buttons[i].y = height - DLG_MARGIN - DLG_BUTTON_H;
	}

	while (!done)
	{
		XEvent ev = WINPR_C_ARRAY_INIT;

		XNextEvent(display, &ev);

		switch (ev.type)
		{
			case Expose:
				if (ev.xexpose.count == 0)
					st.dirty = TRUE;
				break;

			case MapNotify:
				/* drawing does not depend only on Expose, the map is enough to repaint */
				dlg_on_mapped(&st);
				break;

			case ClientMessage:
				if ((Atom)ev.xclient.data.l[0] == st.wm_delete)
				{
					result = 0;
					done = TRUE;
				}
				break;

			case KeyPress:
			{
				char text[16] = WINPR_C_ARRAY_INIT;
				KeySym ks = NoSymbol;
				(void)XLookupString(&ev.xkey, text, sizeof(text) - 1, &ks, nullptr);

				if (ks == XK_Escape)
				{
					result = 0;
					done = TRUE;
				}
				else if ((ks == XK_Tab) || (ks == XK_Right))
				{
					focus = (focus + 1) % 3;
					st.dirty = TRUE;
				}
				else if ((ks == XK_ISO_Left_Tab) || (ks == XK_Left))
				{
					focus = (focus + 2) % 3;
					st.dirty = TRUE;
				}
				else if ((ks == XK_Return) || (ks == XK_KP_Enter) || (ks == XK_space))
				{
					result = buttons[focus].value;
					done = TRUE;
				}
				break;
			}

			case ButtonPress:
				if (ev.xbutton.button != Button1)
					break;
				for (int i = 0; i < 3; i++)
				{
					if (dlg_inside(ev.xbutton.x, ev.xbutton.y, buttons[i].x, buttons[i].y,
					               buttons[i].w, buttons[i].h))
					{
						pressed = i;
						focus = i;
						st.dirty = TRUE;
					}
				}
				break;

			case ButtonRelease:
				if (ev.xbutton.button != Button1)
					break;
				for (int i = 0; i < 3; i++)
				{
					if ((i == pressed) && dlg_inside(ev.xbutton.x, ev.xbutton.y, buttons[i].x,
					                                 buttons[i].y, buttons[i].w, buttons[i].h))
					{
						result = buttons[i].value;
						done = TRUE;
					}
				}
				pressed = -1;
				break;

			case MotionNotify:
			{
				int h = -1;
				for (int i = 0; i < 3; i++)
				{
					if (dlg_inside(ev.xmotion.x, ev.xmotion.y, buttons[i].x, buttons[i].y,
					               buttons[i].w, buttons[i].h))
						h = i;
				}
				if (h != hover)
				{
					hover = h;
					st.dirty = TRUE;
				}
				break;
			}

			default:
				break;
		}

		if (st.dirty && !done)
		{
			cert_draw(&st, &hl, &wl, &ll, &vl, rows, count, buttons, focus, hover);
			dlg_blit(&st);
		}
	}

	rc = result;

out:
	dlg_close(&st);
	dlg_lines_free(&hl);
	dlg_lines_free(&wl);
	dlg_lines_free(&ll);
	dlg_lines_free(&vl);
	free(rows);
	return rc;
}

/* ---------- FreeRDP callbacks ---------- */

/* The core passes the whole PEM when VERIFY_CERT_FLAG_FP_IS_PEM is set, show its SHA-256
 * instead, it is short enough to compare. Returns a newly allocated string, or NULL if the
 * value is not a PEM, the caller then shows the value as it was received.
 */
static char* dlg_fingerprint(const char* value, DWORD flags)
{
	rdpCertificate* cert = nullptr;
	char* fp = nullptr;

	if (!value || !(flags & VERIFY_CERT_FLAG_FP_IS_PEM))
		return nullptr;

	cert = freerdp_certificate_new_from_pem(value);
	if (!cert)
		return nullptr;

	fp = freerdp_certificate_get_fingerprint_by_hash_ex(cert, "SHA256", TRUE);
	freerdp_certificate_free(cert);
	return fp;
}

static BOOL dialogs_available(const xfContext* xfc)
{
	if (!xfc || !xfc->display)
		return FALSE;

	/* credentials and decisions come from stdin or an external askpass helper */
	if (freerdp_settings_get_bool(xfc->common.context.settings, FreeRDP_CredentialsFromStdin))
		return FALSE;
	if (GetEnvironmentVariableA("FREERDP_ASKPASS", nullptr, 0) > 0)
		return FALSE;
	return TRUE;
}

static BOOL dialog_fallback_authenticate(freerdp* instance, char** username, char** password,
                                         char** domain, rdp_auth_reason reason)
{
	const xfContext* xfc = (const xfContext*)instance->context;

	if (!xfc->fallbackAuthenticateEx)
		return FALSE;
	return xfc->fallbackAuthenticateEx(instance, username, password, domain, reason);
}

static BOOL dialog_authenticate_ex(freerdp* instance, char** username, char** password,
                                   char** domain, rdp_auth_reason reason)
{
	char title[DLG_TEXT_BUF] = WINPR_C_ARRAY_INIT;
	char* u = nullptr;
	char* p = nullptr;
	char* d = nullptr;
	xfContext* xfc = (xfContext*)instance->context;
	const char* server = nullptr;
	BOOL need = FALSE;
	int rc = 0;

	WINPR_ASSERT(username);
	WINPR_ASSERT(password);
	WINPR_ASSERT(domain);

	switch (reason)
	{
		case AUTH_RDP:
		case AUTH_TLS:
		case AUTH_NLA:
		case AUTH_RDSTLS:
			/* ask only when something is missing, e.g. complete /u: and /p: on the command
			 * line must not show the dialog */
			need = !(*username && **username && *password);
			break;
		default:
			/* PIN and gateway prompts keep the previous behavior */
			return dialog_fallback_authenticate(instance, username, password, domain, reason);
	}

	if (!need)
		return TRUE;

	if (!dialogs_available(xfc))
	{
		WLog_INFO(TAG, "credentials dialog not available, using the previous callback");
		return dialog_fallback_authenticate(instance, username, password, domain, reason);
	}

	server = freerdp_settings_get_server_name(xfc->common.context.settings);
	(void)snprintf(title, sizeof(title), "Credenciais necessarias para %s",
	               server ? server : "servidor");

	WLog_DBG(TAG, "showing credentials dialog for %s", server ? server : "server");
	rc = xf_xlib_authenticate_dialog(xfc->display, title, *username, *domain, &u, &p, &d);
	WLog_DBG(TAG, "credentials dialog result %d", rc);
	if (rc == XF_DIALOG_UNAVAILABLE)
		return dialog_fallback_authenticate(instance, username, password, domain, reason);
	if (rc != 1)
		return FALSE;

	free(*username);
	free(*password);
	free(*domain);
	*username = u;
	*password = p;
	*domain = d;
	return TRUE;
}

static const char* cert_type(DWORD flags)
{
	if (flags & (DWORD)VERIFY_CERT_FLAG_GATEWAY)
		return "RDP-Gateway";
	if (flags & (DWORD)VERIFY_CERT_FLAG_REDIRECT)
		return "RDP-Redirect";
	return "RDP-Server";
}

static DWORD dialog_verify_certificate_ex(freerdp* instance, const char* host, UINT16 port,
                                          const char* common_name, const char* subject,
                                          const char* issuer, const char* fingerprint, DWORD flags)
{
	xfContext* xfc = (xfContext*)instance->context;
	char title[DLG_TEXT_BUF] = WINPR_C_ARRAY_INIT;
	char heading[DLG_TEXT_BUF] = WINPR_C_ARRAY_INIT;
	char hostport[DLG_TEXT_BUF] = WINPR_C_ARRAY_INIT;
	const char* warning = "O certificado nao pode ser verificado. Ele pode ser autoassinado, "
	                      "estar expirado ou nao ter a CA na loja de confianca.";
	xfDialogField fields[5] = { 0 };
	char* fp = nullptr;
	int rc = 0;

	if (!dialogs_available(xfc))
	{
		WLog_INFO(TAG, "certificate dialog not available, using the previous callback");
		if (!xfc->fallbackVerifyCertificateEx)
			return 0;
		return xfc->fallbackVerifyCertificateEx(instance, host, port, common_name, subject, issuer,
		                                        fingerprint, flags);
	}

	(void)snprintf(title, sizeof(title), "Certificado de %s:%" PRIu16, host, port);
	(void)snprintf(heading, sizeof(heading), "Novo certificado (%s) para %s:%" PRIu16,
	               cert_type(flags), host, port);
	(void)snprintf(hostport, sizeof(hostport), "%s:%" PRIu16, host, port);
	fp = dlg_fingerprint(fingerprint, flags);

	fields[0].label = "Servidor";
	fields[0].value = hostport;
	fields[1].label = "Nome comum";
	fields[1].value = common_name;
	fields[2].label = "Assunto";
	fields[2].value = subject;
	fields[3].label = "Emissor";
	fields[3].value = issuer;
	fields[4].label = "SHA-256";
	fields[4].value = fp ? fp : fingerprint;

	WLog_DBG(TAG, "showing certificate dialog for %s:%" PRIu16, host, port);
	rc = xf_xlib_certificate_dialog(xfc->display, title, heading, warning, fields,
	                                ARRAYSIZE(fields));
	WLog_DBG(TAG, "certificate dialog result %d", rc);
	free(fp);
	if (rc == XF_DIALOG_UNAVAILABLE)
	{
		if (!xfc->fallbackVerifyCertificateEx)
			return 0;
		return xfc->fallbackVerifyCertificateEx(instance, host, port, common_name, subject, issuer,
		                                        fingerprint, flags);
	}
	return (DWORD)rc;
}

static DWORD dialog_verify_changed_certificate_ex(freerdp* instance, const char* host, UINT16 port,
                                                  const char* common_name, const char* subject,
                                                  const char* issuer, const char* new_fingerprint,
                                                  const char* old_subject, const char* old_issuer,
                                                  const char* old_fingerprint, DWORD flags)
{
	xfContext* xfc = (xfContext*)instance->context;
	char title[DLG_TEXT_BUF] = WINPR_C_ARRAY_INIT;
	char heading[DLG_TEXT_BUF] = WINPR_C_ARRAY_INIT;
	char hostport[DLG_TEXT_BUF] = WINPR_C_ARRAY_INIT;
	const char* warning =
	    "O certificado deste servidor MUDOU desde a ultima conexao. Isso pode indicar uma "
	    "adulteracao. Confirme com o administrador do servidor antes de aceitar.";
	xfDialogField fields[8] = { 0 };
	char* fp_new = nullptr;
	char* fp_old = nullptr;
	int rc = 0;

	if (!dialogs_available(xfc))
	{
		WLog_INFO(TAG, "changed certificate dialog not available, using the previous callback");
		if (!xfc->fallbackVerifyChangedCertificateEx)
			return 0;
		return xfc->fallbackVerifyChangedCertificateEx(instance, host, port, common_name, subject,
		                                               issuer, new_fingerprint, old_subject,
		                                               old_issuer, old_fingerprint, flags);
	}

	(void)snprintf(title, sizeof(title), "Certificado alterado de %s:%" PRIu16, host, port);
	(void)snprintf(heading, sizeof(heading), "Certificado alterado (%s) para %s:%" PRIu16,
	               cert_type(flags), host, port);
	(void)snprintf(hostport, sizeof(hostport), "%s:%" PRIu16, host, port);
	fp_new = dlg_fingerprint(new_fingerprint, flags);
	fp_old = dlg_fingerprint(old_fingerprint, flags);

	fields[0].label = "Servidor";
	fields[0].value = hostport;
	fields[1].label = "Nome comum";
	fields[1].value = common_name;
	fields[2].label = "Novo assunto";
	fields[2].value = subject;
	fields[3].label = "Novo emissor";
	fields[3].value = issuer;
	fields[4].label = "Nova SHA-256";
	fields[4].value = fp_new ? fp_new : new_fingerprint;
	fields[5].label = "Assunto anterior";
	fields[5].value = old_subject;
	fields[6].label = "Emissor anterior";
	fields[6].value = old_issuer;
	fields[7].label = "SHA-256 anterior";
	fields[7].value = fp_old ? fp_old : old_fingerprint;

	WLog_DBG(TAG, "showing certificate dialog for %s:%" PRIu16, host, port);
	rc = xf_xlib_certificate_dialog(xfc->display, title, heading, warning, fields,
	                                ARRAYSIZE(fields));
	WLog_DBG(TAG, "certificate dialog result %d", rc);
	free(fp_new);
	free(fp_old);
	if (rc == XF_DIALOG_UNAVAILABLE)
	{
		if (!xfc->fallbackVerifyChangedCertificateEx)
			return 0;
		return xfc->fallbackVerifyChangedCertificateEx(instance, host, port, common_name, subject,
		                                               issuer, new_fingerprint, old_subject,
		                                               old_issuer, old_fingerprint, flags);
	}
	return (DWORD)rc;
}

BOOL xf_dialogs_install(xfContext* xfc)
{
	freerdp* instance = nullptr;

	if (!xfc)
		return FALSE;

	instance = xfc->common.context.instance;
	WINPR_ASSERT(instance);

	/* already installed, e.g. on reconnect: keep the saved fallbacks untouched */
	if (instance->AuthenticateEx == dialog_authenticate_ex)
		return TRUE;

	xfc->fallbackAuthenticateEx = instance->AuthenticateEx;
	xfc->fallbackVerifyCertificateEx = instance->VerifyCertificateEx;
	xfc->fallbackVerifyChangedCertificateEx = instance->VerifyChangedCertificateEx;

	instance->AuthenticateEx = dialog_authenticate_ex;
	instance->VerifyCertificateEx = dialog_verify_certificate_ex;
	instance->VerifyChangedCertificateEx = dialog_verify_changed_certificate_ex;
	WLog_DBG(TAG, "X11 dialogs installed for credentials and certificate verification");
	return TRUE;
}
