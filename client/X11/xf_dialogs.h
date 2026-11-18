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

#ifndef FREERDP_CLIENT_X11_DIALOGS_H
#define FREERDP_CLIENT_X11_DIALOGS_H

#include <stddef.h>

#include <winpr/wtypes.h>

#include <X11/Xlib.h>

#include "xf_types.h"

/* Result values shared by the dialog functions */
#define XF_DIALOG_UNAVAILABLE (-1)

typedef struct
{
	const char* label;
	const char* value;
} xfDialogField;

/* Replace the authentication and certificate callbacks of the instance with the X11
 * dialogs. The previous callbacks are kept and used whenever a dialog cannot be shown.
 */
BOOL xf_dialogs_install(xfContext* xfc);

/* Returns 1 if the user confirmed credentials (the out_ strings are newly allocated),
 * 0 if the user cancelled, XF_DIALOG_UNAVAILABLE if no dialog could be created.
 */
int xf_xlib_authenticate_dialog(Display* display, const char* title, const char* username,
                                const char* domain, char** out_username, char** out_password,
                                char** out_domain);

/* Returns 0 to deny, 1 to accept permanently, 2 to accept temporarily, XF_DIALOG_UNAVAILABLE
 * if no dialog could be created.
 */
int xf_xlib_certificate_dialog(Display* display, const char* title, const char* heading,
                               const char* warning, const xfDialogField* fields, size_t count);

#endif /* FREERDP_CLIENT_X11_DIALOGS_H */
