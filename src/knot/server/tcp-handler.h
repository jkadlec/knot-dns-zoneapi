/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
/*!
 * \file tcp-handler.h
 *
 * \author Marek Vavrusa <marek.vavusa@nic.cz>
 *
 * \brief TCP sockets threading model.
 *
 * The master socket distributes incoming connections among
 * the worker threads ("buckets"). Each threads processes it's own
 * set of sockets, and eliminates mutual exclusion problem by doing so.
 *
 * \addtogroup server
 * @{
 */

#pragma once

#include "knot/server/dthreads.h"

#define TCP_SWEEP_INTERVAL 2 /*!< [secs] granularity of connection sweeping. */
#define TCP_BACKLOG_SIZE  10 /*!< TCP listen backlog size. */

/*!
 * \brief Accept a TCP connection.
 * \param fd Associated socket.
 *
 * \retval Created connection fd if success.
 * \retval <0 on error.
 */
int tcp_accept(int fd);

/*!
 * \brief TCP handler thread runnable.
 *
 * Listens to both bound TCP sockets for client connections and
 * serves TCP clients. This runnable is designed to be used as coherent
 * and implements cancellation point.
 *
 * \param thread Associated thread from DThreads unit.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL invalid parameters.
 */
int tcp_master(dthread_t *thread);

/*!
 * \brief Destructor for TCP handler thread.
 */
int tcp_master_destruct(dthread_t *thread);

/*! @} */
