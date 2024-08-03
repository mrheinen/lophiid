// Lophiid distributed honeypot
// Copyright (C) 2024 Niels Heinen
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the
// Free Software Foundation; either version 2 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
// for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
//
package metrics

// Buckets for metrics to use in histograms,
var FastResponseTimebuckets = []float64{.0001, .0005, .001, .002, .003, .004, .005, .006, .007, .008, .009, .01, .025, .05, .1, .5, 1, 2.5, 5, 10}
var MediumResponseTimebuckets = []float64{.001, .002, .003, .004, .005, .006, .007, .008, .009, .01, .025, .05, .1, .2, .3, .4, .5, .6, .7, .8, .9, 1, 1.2, 1.4, 1.6, 1.8, 2, 2.5, 3, 3.5, 4, 5, 6, 7, 8, 9, 10}
var SlowResponseTimebuckets = []float64{.1, .2, .3, .4, .5, .6, .7, .8, .9, 1, 1.2, 1.4, 1.6, 1.8, 2, 2.5, 3, 3.5, 4, 5, 6, 7, 8, 9, 10, 15, 20, 30, 40, 50, 60, 120, 300, 600, 900, 1200}
