#P- and C-State MSR Plugin for Score-P

##Compilation and Installation

###Prerequisites

To compile this plugin, you need:

* GCC compiler

* `libpthread`

* CMake

* Score-P

* Reading msr directly:

    The kernel module `msr` should be active (you might use `modprobe`) and you should have reading
    access to `/dev/cpu/*/msr`.

* Reading energy values through `x86_adapt`:

    The kernel module `x86_adapt_driver` should be active and and should have reading access to
    `/dev/x86_adapt/cpu/*`.

###Build Options

* For `SCOREP`, `VT`, `X86A`, `MSR` as `<PREFIX>`

    * `-D<PREFIX>_DIR`

        A folder that holds a lib and include folder for the specific software (e.g., Score-P).

    * `-D<PREFIX>_INC`

        The include folder that holds the header for a specific software (e.g., Score-P).

    * `-D<PREFIX>_LIB`

        The library folder that holds the libraries for a specific software (e.g., Score-P).

* For `X86A`, `MSR` as `<PREFIX>`

    * `-D<PREFIX>_STATIC` (default=ON)

        Whether to include the static version of this library (options=OFF/ON).

###Building

1. Create build directory

        mkdir build
        cd build

2. Invoking CMake

        cmake ..

    Example for a prebuild static linked `libmsr` which is not in the default path:

        cmake .. -DMSR_INC=$HOME/x86_energy -DMSR_LIB=$HOME/x86_energy/build -DMSR_STATIC=ON -DMSR_BUILD=OFF

    Example for building `msr` library and linking it statically:

        cmake .. -DMSR_DIR=$HOME/x86_energy

3. Invoking make

        make

4. Copy it to a location listed in `LD_LIBRARY_PATH` or add current path to `LD_LIBRARY_PATH` with

        export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:`pwd`

> *Note:*
>
> If `libmsr`/`x86_adapt` is linked dynamically then the location of `libmsr`/`x86_adapt` has to be in
> the `LD_LIBRARY_PATH` as well.

##Usage

###Score-P

To add a kernel event counter to your trace, you have to specify the environment
variables `SCOREP_METRIC_PLUGINS` and `SCOREP_METRIC_PCSTATES_PLUGIN`.

Load the PC plugin library

    SCOREP_METRIC_PLUGINS="pcstates"

###VampirTrace

To add a kernel event counter to your trace, you have to specify the environment variable
`VT_PLUGIN_CNTR_METRICS`.

###Common

`VT_PLUGIN_CNTR_METRICS`/`SCOREP_METRIC_PCSTATES_PLUGIN` specifies the software events that shall be
recorded when tracing an application. You can add the following metrics (they have to be prefixed
with `pcstates_` for VampirTrace):

* `aperf`

    Collect actual frequency of a certain CPU core.

* `mperf`

    Collect reference frequency of the cpu core.

* `C[3|6|7]`

    Collect time spent in specific C-State (Only Intel).

* `PC[3|6|7]`

    Collect time spent in specific package C-State (Only Intel).

* `C*`

    Collect time spent in all C-States (Only Intel).

* `PC*`

    Collect time spent in all package C-States (Only Intel).

* `*`

    Collect all supported events.

E.g. (for Score-P):

    export SCOREP_METRIC_PCSTATES_PLUGIN="aperf:C6:C7"

or

    export SCOREP_METRIC_PCSTATES_PLUGIN="*"

or (for VampirTrace):

    export VT_PLUGIN_CNTR_METRIC="pcstates_aperf:pcstates_C6:pcstates_C7"

or

    export VT_PLUGIN_CNTR_METRIC="pcstates_*"

> *Note:*

> All tasks traced with this plugin should be pinned to one specific core! Use `numactl`, `taskset`,
> `GOMP_CPU_AFFINITY`, …

> Otherwise, the presented data might not be meaningful. For every traced task, one file descriptor
> is kept open to read the msr registers. If a task is not pinned, this file descriptor is opened and
> closed for every read.

###If anything fails

1. Check whether the plugin library can be loaded from the `LD_LIBRARY_PATH`.

2. Check whether you are allowed to read `/dev/cpu/*/msr`.

3. Write a mail to the author.

##Authors

* Robert Schoene (robert.schoene at tu-dresden dot de)

* Michael Werner (michael.werner3 at tu-dresden dot de)
