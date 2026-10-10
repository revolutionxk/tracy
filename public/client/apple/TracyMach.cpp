// (this file gets included by TracySysTrace.cpp)

#ifndef __APPLE__
#error this file can only be compiled for Apple targets
#endif

#include <atomic>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <ptrauth.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <vector>

#include "../TracyProfiler.hpp"
#include "../TracyStringHelpers.hpp"
#include "../TracyThread.hpp"

namespace tracy
{

struct SysTraceApple
{
    std::atomic<bool> active { false };
    int samplingHz = 1000;
    static SysTraceApple& Get()
    {
        static SysTraceApple systrace = {};
        return systrace;
    }
};

struct SysTraceThread
{
    mach_port_t port;
    uint32_t id;
};

static void SysTraceEmitCallstackSample( uint32_t threadId, int64_t timestamp, const uint64_t* frames, int depth )
{
#ifdef TRACY_ON_DEMAND
    if( !GetProfiler().IsConnected() ) return;
#endif

    auto trace = (uint64_t*)tracy_malloc( ( 1 + depth ) * sizeof( uint64_t ) );
    trace[0] = (uint64_t)depth;
    memcpy( trace + 1, frames, depth * sizeof( uint64_t ) );

    TracyLfqPrepare( QueueType::CallstackSample );
    MemWrite( &item->callstackSampleFat.time, timestamp );
    MemWrite( &item->callstackSampleFat.thread, threadId );
    MemWrite( &item->callstackSampleFat.ptr, (uint64_t)trace );
    TracyLfqCommit;
}

static uint64_t SysTraceStackLimit( uint64_t sp )
{
    mach_vm_address_t address = sp;
    mach_vm_size_t size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object = MACH_PORT_NULL;
    if( mach_vm_region( mach_task_self(), &address, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &object ) != KERN_SUCCESS ) return sp;
    if( address > sp || ( info.protection & VM_PROT_READ ) == 0 ) return sp;
    return address + size;
}

static int SysTraceBacktrace( uint64_t* frames, int maxDepth, uint64_t pc, uint64_t fp, uint64_t sp )
{
    constexpr uint64_t MaxStackSpan = 8ull * 1024 * 1024;
    constexpr uint64_t RecordSize = 2 * sizeof( uint64_t );

    int depth = 0;
    frames[depth++] = pc;

    // NOTE: frame-pointer walk for now... It should be fine since the ABI
    // mandates it on ARM64 (and on x64 Apple clang preserves it by default)
    uint64_t lower = sp;
    const uint64_t limit = SysTraceStackLimit( sp );
    const uint64_t upper = limit - sp < MaxStackSpan ? limit : sp + MaxStackSpan;
    while( depth < maxDepth )
    {
        if( fp == 0 || fp < lower || fp > upper - RecordSize || ( fp & ( sizeof( uint64_t ) - 1 ) ) ) break;
        const auto record = (const uint64_t*)fp;
        // [framePtr + 0] = saved frame pointer (previous frame)
        // [framePtr + 1] = return address, may be PAC-signed on ARM64
        const uint64_t next = record[0];
        const uint64_t ret = (uint64_t)ptrauth_strip( (void*)record[1], ptrauth_key_return_address );
        if( ret == 0 ) break;
        frames[depth++] = ret;
        if( next <= fp ) break;
        lower = fp + RecordSize;
        fp = next;
    }
    return depth;
}

static void SysTraceSampleThread( const SysTraceThread& thread )
{
    const int64_t t0 = Profiler::GetTime();
    if( thread_suspend( thread.port ) != KERN_SUCCESS ) return;
    const int64_t t1 = Profiler::GetTime();
    const int64_t timestamp = t0 + ( t1 - t0 ) / 2;

#if defined(__aarch64__)
    arm_thread_state64_t state;
    mach_msg_type_number_t stateCount = ARM_THREAD_STATE64_COUNT;
    const kern_return_t kr = thread_get_state( thread.port, ARM_THREAD_STATE64, (thread_state_t)&state, &stateCount );
#elif defined(__x86_64__)
    x86_thread_state64_t state;
    mach_msg_type_number_t stateCount = x86_THREAD_STATE64_COUNT;
    const kern_return_t kr = thread_get_state( thread.port, x86_THREAD_STATE64, (thread_state_t)&state, &stateCount );
#else
    #error "unsupported architecture"
#endif

    if( kr != KERN_SUCCESS )
    {
        thread_resume( thread.port );
        return;
    }

    constexpr int MaxDepth = 192;
    uint64_t frames [MaxDepth];

#if defined(__aarch64__)
    if( arm_thread_state64_get_pc( state ) == 0 || arm_thread_state64_get_sp( state ) == 0 )
    {
        thread_resume( thread.port );
        return;
    }
    int depth = SysTraceBacktrace( frames, MaxDepth, arm_thread_state64_get_pc( state ), arm_thread_state64_get_fp( state ), arm_thread_state64_get_sp( state ) );
    const uint64_t link = (uint64_t)ptrauth_strip( (void*)arm_thread_state64_get_lr( state ), ptrauth_key_return_address );
#elif defined(__x86_64__)
    if( state.__rip == 0 || state.__rsp == 0 )
    {
        thread_resume( thread.port );
        return;
    }
    int depth = SysTraceBacktrace( frames, MaxDepth, state.__rip, state.__rbp, state.__rsp );
    const uint64_t link = 0;
#endif

    depth = SysTraceRunSampleHook( thread.id, frames, depth, MaxDepth, link );

    thread_resume( thread.port );

    if( depth > 0 ) SysTraceEmitCallstackSample( thread.id, timestamp, frames, depth );
}

static void SysTraceWait( uint64_t deadline )
{
    mach_wait_until( deadline );
}

static uint64_t SysTraceRngInit()
{
    uint64_t seed = mach_absolute_time();
    seed ^= (uint64_t)(uintptr_t)&seed;
    return seed;
}

static uint32_t SysTraceRngNext( uint64_t& rng, uint32_t range )
{
    rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
    return (uint32_t)( rng % range );
}

static void SysTraceWatch()
{
    auto& systrace = SysTraceApple::Get();

    const mach_port_t selfThread = mach_thread_self();
    mach_timebase_info_data_t timebase;
    mach_timebase_info( &timebase );
    const uint64_t samplingPeriodNs = 1000000000ULL / systrace.samplingHz;
    const uint64_t periodMach = samplingPeriodNs * timebase.denom / timebase.numer;

    std::vector<SysTraceThread> runningThreads;
    std::vector<SysTraceThread> waitingThreads;

    uint64_t rng = SysTraceRngInit();

    uint64_t deadline = mach_absolute_time();
    while( systrace.active.load( std::memory_order_relaxed ) )
    {
        SysTraceWait(deadline);
        deadline = mach_absolute_time() + periodMach;

#ifdef TRACY_ON_DEMAND
        if( !GetProfiler().IsConnected() ) continue;
#endif

        thread_act_array_t threads;
        mach_msg_type_number_t threadCount;
        if( task_threads( mach_task_self(), &threads, &threadCount ) != KERN_SUCCESS ) continue;

        runningThreads.clear();
        waitingThreads.clear();

        for( mach_msg_type_number_t i = 0; i < threadCount; i++ )
        {
            const mach_port_t tid = threads[i];
            if( tid == selfThread ) continue;

            thread_basic_info_data_t info;
            mach_msg_type_number_t infoCount = THREAD_BASIC_INFO_COUNT;
            if( thread_info( tid, THREAD_BASIC_INFO, (thread_info_t)&info, &infoCount ) != KERN_SUCCESS ) continue;
            if( info.flags & TH_FLAGS_IDLE ) continue;  // kernel idle thread, not user code

            thread_identifier_info_data_t identifier;
            mach_msg_type_number_t identifierCount = THREAD_IDENTIFIER_INFO_COUNT;
            if( thread_info( tid, THREAD_IDENTIFIER_INFO, (thread_info_t)&identifier, &identifierCount ) != KERN_SUCCESS ) continue;

            const SysTraceThread thread { tid, uint32_t( identifier.thread_id ) };
            if( info.run_state == TH_STATE_RUNNING )
                runningThreads.push_back( thread );
            else
                waitingThreads.push_back( thread );
        }

        for( const auto& thread : runningThreads )
            SysTraceSampleThread( thread );

        while( !waitingThreads.empty() )
        {
            if( mach_absolute_time() >= deadline ) break;
            const uint32_t idx = SysTraceRngNext( rng, (uint32_t)waitingThreads.size() );
            SysTraceSampleThread( waitingThreads[idx] );
            std::swap( waitingThreads[idx], waitingThreads.back() );
            waitingThreads.pop_back();
        }

        for( mach_msg_type_number_t i = 0; i < threadCount; i++ )
            mach_port_deallocate( mach_task_self(), threads[i] );
        vm_deallocate( mach_task_self(), (vm_address_t)threads, sizeof(thread_t) * threadCount );
    }
    mach_port_deallocate( mach_task_self(), selfThread );
}

void SysTraceWorker( void* )
{
    ThreadExitHandler threadExitHandler;
    SetThreadName( "Tracy Mach Watchdog" );
    InitAllocator();
    SysTraceWatch();
}

bool SysTraceStart( int64_t& samplingPeriod )
{
    auto& systrace = SysTraceApple::Get();

    bool expected = false;
    if( !systrace.active.compare_exchange_strong( expected, true, std::memory_order_relaxed ) )
        return false;

    systrace.samplingHz = GetSamplingFrequency();
    samplingPeriod      = SamplingFrequencyToPeriodNs( systrace.samplingHz );
    return true;
}

void SysTraceStop()
{
    auto& systrace = SysTraceApple::Get();
    systrace.active.store( false, std::memory_order_relaxed );
}

void SysTraceGetExternalName( uint64_t thread, const char*& threadName, const char*& name )
{
    threadName = nullptr;

    thread_act_array_t threads;
    mach_msg_type_number_t threadCount;
    if( task_threads( mach_task_self(), &threads, &threadCount ) == KERN_SUCCESS )
    {
        for( mach_msg_type_number_t i = 0; i < threadCount; i++ )
        {
            if( !threadName )
            {
                thread_identifier_info_data_t identifier;
                mach_msg_type_number_t identifierCount = THREAD_IDENTIFIER_INFO_COUNT;
                if( thread_info( threads[i], THREAD_IDENTIFIER_INFO, (thread_info_t)&identifier, &identifierCount ) == KERN_SUCCESS && uint32_t( identifier.thread_id ) == uint32_t( thread ) )
                {
                    thread_extended_info_data_t extended;
                    mach_msg_type_number_t extendedCount = THREAD_EXTENDED_INFO_COUNT;
                    if( thread_info( threads[i], THREAD_EXTENDED_INFO, (thread_info_t)&extended, &extendedCount ) == KERN_SUCCESS && extended.pth_name[0] != '\0' )
                        threadName = CopyString( extended.pth_name );
                }
            }
            mach_port_deallocate( mach_task_self(), threads[i] );
        }
        vm_deallocate( mach_task_self(), (vm_address_t)threads, sizeof( thread_t ) * threadCount );
    }

    if( !threadName ) threadName = CopyString( "???", 3 );

    TracyLfqPrepare( QueueType::TidToPid );
    MemWrite( &item->tidToPid.tid, thread );
    MemWrite( &item->tidToPid.pid, (uint64_t)getpid() );
    TracyLfqCommit;

    name = CopyStringFast( getprogname() );
}

} // namespace tracy
