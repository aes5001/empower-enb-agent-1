/* Copyright (c) 2018 Kewin Rausch
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* The visibility header.
 *
 * Provides definition to identify if a symbol is internal to the library or if
 * it will be visible in the ELF symbol table.
 */

#ifndef __EMAGE_VISIBILITY_H
#define __EMAGE_VISIBILITY_H

/* The symbol will be visible and usable by external module */
#define EMAGE_API       __attribute__ ((visibility ("default")))

/* The symbol will be used only within this library */
#define INTERNAL        __attribute__ ((visibility ("hidden")))

#endif /* __EMAGE_VISIBILITY_H */
