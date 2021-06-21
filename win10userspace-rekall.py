
from rekall.plugins.windows import common



class Win10UserSpace(common.WinProcessFilter):

    def __init__(self, *args, **kwargs):
        super(Win10UserSpace, self).__init__(*args, **kwargs)
        self.session.profile.add_types({
            '_SEGMENT_HEAP': [0x5f0, {
                'TotalReservedPages': [0x0, ['unsigned long long']],
                'TotalCommittedPages': [0x8, ['unsigned long long']],
                'Signature': [0x10, ['unsigned long']],
                'GlobalFlags': [0x14, ['unsigned long']],
                'FreeCommittedPages': [0x18, ['unsigned long long']],
                'Interceptor': [0x20, ['unsigned long']],
                'ProcessHeapListIndex': [0x24, ['unsigned short']],
                'GlobalLockCount': [0x26, ['unsigned short']],
                'GlobalLockOwner': [0x28, ['unsigned long']],
                'LargeMetadataLock': [0x30, ['_RTL_SRWLOCK']],
                'LargeAllocMetadata': [0x38, ['_RTL_RB_TREE']],
                'LargeReservedPages': [0x48, ['unsigned long long']],
                'LargeCommittedPages': [0x50, ['unsigned long long']],
                'SegmentAllocatorLock': [0x58, ['_RTL_SRWLOCK']],
                'SegmentListHead': [0x60, ['_LIST_ENTRY']],
                'SegmentCount': [0x70, ['unsigned long long']],
                'FreePageRanges': [0x78, ['_RTL_RB_TREE']],
                'StackTraceInitVar': [0x88, ['_RTL_RUN_ONCE']],
                'ContextExtendLock': [0x90, ['_RTL_SRWLOCK']],
                'AllocatedBase': [0x98, ['pointer64', ['unsigned char']]],
                'UncommittedBase': [0xa0, ['pointer64', ['unsigned char']]],
                'ReservedLimit': [0xa8, ['pointer64', ['unsigned char']]],
                'VsContext': [0xb0, ['_HEAP_VS_CONTEXT']],
                'LfhContext': [0x120, ['_HEAP_LFH_CONTEXT']],
            }],
            '_HEAP_LARGE_ALLOC_DATA': [0x28, {
                'TreeNode': [0x0, ['_RTL_BALANCED_NODE']],
                'VirtualAddress': [0x18, ['unsigned long long']],
                'UnusedBytes': [0x18,
                                ['BitField', dict(start_bit=0, end_bit=16, native_type='unsigned long long')]],
                'ExtraPresent': [0x20,
                                 ['BitField', dict(start_bit=0, end_bit=1, native_type='unsigned long long')]],
                'Spare': [0x20, ['BitField', dict(start_bit=1, end_bit=12, native_type='unsigned long long')]],
                'AllocatedPages': [0x20,
                                   ['BitField', dict(start_bit=12, end_bit=64, native_type='unsigned long long')]],
            }]
        })

    __name = "win10userspace"

    table_header = [
        dict(name='start', style="address"),
        dict(name="end", style="address"),
        dict(name='used', style="address"),
        dict(name='size', style="address"),
        dict(name='protect', width=20),
        dict(name='type', width=7),
        dict(name='description')
    ]

    def column_types(self):
        return dict(
            start=self.session.profile.Pointer(),
            end=self.session.profile.Pointer(),
            used=self.session.profile.Pointer(),
            size=self.session.profile.Pointer(),
            protect=str,
            type=str,
            description=str)

    def collect(self):
        for task, user_allocs, addresses, unreferenced in self.calculate():
            sorted(addresses)
            for addr in addresses:
                alloc = user_allocs[addr]
                description = alloc.description()

                yield dict(
                        start=alloc.start_address,
                        end=alloc.end_address,
                        used=alloc.allocated,
                        size=alloc.size,
                        protect=alloc.permissions,
                        type=alloc.type,
                        description=description)


    def calculate(self):
        self.wow64 = False

        tasks_list = list(self.filter_processes())

        for task in tasks_list:
            if hasattr(task, 'WoW64Process') and task.WoW64Process.v() != 0:
                self.wow64 = True
            for data in self.analyze(task):
                yield data


    def analyze(self, task):
        pid = task.UniqueProcessId

        self.ps_ad = task.get_process_address_space()
        self.dtb = task.dtb
        user_pages = self.get_user_pages()

        self.user_allocs = {}
        self.unreferenced = []
        self.get_user_allocations(task, user_pages)

        self.get_kernel_metadata()

        self.get_user_metadata(self.ps_ad, task, pid)

        addresses = self.user_allocs.keys()
        addresses = sorted(addresses)
        #return user allocation information
        yield task, self.user_allocs, addresses, self.unreferenced


    def get_user_pages(self):
        all_pages = []
        user_pages = []
        for run in self.ps_ad.get_mappings(end=0x7ffffffeffff):
            all_pages.append([run.start, run.length])
        if self.wow64:
            for page in all_pages:
                if page[0] < 0x80000000:
                    user_pages.append(page)
            return user_pages
        else:
            for page in all_pages:
                if page[0] < 0x800000000000:
                    user_pages.append(page)
            return user_pages


    def get_user_allocations(self, task, user_pages):
        """Traverse the VAD and get the user allocations and locate
            any unreferenced memory pages"""
        for vad in task.RealVadRoot.traverse():
            alloc = Win10UserSpace.UserAlloc(vad)
            user_pages = alloc.pages_allocated(user_pages)
            self.user_allocs[alloc.start_address] = alloc
        self.unreferenced = user_pages


    def get_kshared(self):
        """Find the _KSHARED_USER_DATA structure @ 7FFE0000"""
        pages = []
        if self.wow64:
            for [start, size] in self.unreferenced:
                if start == 0x7FFE0000:
                    alloc = Win10UserSpace.UserAlloc(None, start, size,
                                                "KSHARED_USER_DATA")
                    self.user_allocs[start] = alloc
                else:
                    pages.append([start, size])
            for alloc in self.user_allocs.values():
                if alloc.vad.Start == 0x7FFE0000:
                    self.user_allocs[alloc.vad.Start].add_metadata("KSHARED_USER_DATA")
            self.unreferenced = pages
        else:
            for [start, size] in self.unreferenced:
                if start == 0x7FFFFFFE0000:
                    alloc = Win10UserSpace.UserAlloc(None, start, size,
                                                "KSHARED_USER_DATA")
                    self.user_allocs[start] = alloc
                else:
                    pages.append([start, size])
            self.unreferenced = pages


    def get_kernel_metadata(self):
        """Get file object and section object metadata"""
        self.get_files()
        self.get_sections()

    def get_files(self):
        """Check each VAD for a file object"""
        for alloc in self.user_allocs.values():
            if alloc.vad:
                file_object = None
                try:
                    file_object = alloc.vad.ControlArea.FilePointer
                except:
                    continue
                if file_object and file_object.is_valid():
                    filename = str(file_object.file_name_with_drive())
                    if filename != "":
                        alloc.add_file(filename)


    def get_sections(self):
        """Link each section to a user allocation"""
        for alloc in self.user_allocs.values():
            if alloc.vad:
                try:
                    if alloc.vad.ControlArea != None:
                        alloc.type = "Shared"
                except:
                    continue


    def get_user_metadata(self, ps_ad, task, pid):
        """Get the metadata from the userspace"""
        #Process Environment Block
        peb = task.Peb
        if not peb.is_valid():
            return
        try:
            for alloc in self.user_allocs.values():
                if alloc.start_address <= peb.v() <= alloc.end_address:
                    self.user_allocs[alloc.start_address].add_metadata("PEB", offset = hex(peb.v()))
                    break
        except:
            pass
        #Data from PEB
        gdi_handles, size = self.get_peb_data(peb)
        #Scan handle table for possible allocations
        self.get_heaps(ps_ad, peb)
        #Thread Environment Block and Stacks
        pcb = task.Pcb
        tebs = self.get_tebs(ps_ad, pcb)
        #Track the thread number
        count = 0
        for teb in tebs:
            self.get_stack(teb, count)
            count += 1
        count = 0
        #Check wow64 process
        if self.wow64:
            teb32s = self.get_teb32s(tebs, ps_ad)
            for teb32 in teb32s:
                self.get_wow64_stack(teb32, count)
                count += 1


    def get_peb_data(self, peb):
        """Get the metadata from the PEB"""
        fields = ["ProcessParameters", "AnsiCodePageData", "Ldr"
                  "SystemDefaultActivationContextData", "ActivationContextData",
                  "GdiSharedHandleTable", "pShimData", "pContextData",
                  "WerRegistrationData", "LeapSecondData", "ApiSetMap"]

        gdi = 0
        size = 0
        for field in fields:
            try:
                data = peb.m(field)
                addr = data.v()
                if addr == 0:
                    continue
                if not(addr in self.user_allocs):
                    continue
                #field specific information
                if field == "GdiSharedHandleTable":
                    #save for individual analysis
                    gdi = addr
                    size = self.user_allocs[addr].size
                elif field == "AnsiCodePageData":
                    #rename this field in output
                    field = "CodePage"
                elif field == "ProcessParameters":
                    #get the environment
                    environment = data.Environment.v()
                    self.user_allocs[environment].add_metadata("Environment")
                #add the metadata to the user alloc
                self.user_allocs[addr].add_metadata(field)
            except:
                continue
        return gdi, size


    def get_heaps(self, ps_ad, peb):
        """Get the heaps and heap related data structures"""

        heap_count = 0

        heaps_list = list(peb.ProcessHeaps)

        #add shared heap to list
        heaps_list.append(peb.ReadOnlySharedMemoryBase.dereference_as("_HEAP"))

        #get heap objects
        heap_objects = []
        for heap in heaps_list:
            heap_objects.append([heap.v(),heap])

        #process each heap for metadata
        data = []
        for address, heap in heap_objects:
            if heap_count == len(heaps_list) - 1:
                #shared heap
                heap_info = str(heap_count) + " (Shared)"
            else:
                heap_info = str(heap_count)
            #add heap
            if not(heap.is_valid()):
                heap_text = "Heap {0} (Unreadable)".format(heap_info)
                data.append([address, heap_text])
                heap_count += 1
                continue
            is_nt_heap = False
            if heap.SegmentSignature == 0xffeeffee:
                data.append([address, "Heap {0} NT Heap".format(heap_info)])
                is_nt_heap = True
            else:
                data.append([address, "Heap {0} Segment Heap".format(heap_info)])
            if is_nt_heap:
                for virtual_alloc in self.get_heap_virtual_allocs(ps_ad, heap,
                                                                  heap_info):
                    data.append(virtual_alloc)
                #parse for heap segments
                for segment in self.get_heap_segments(ps_ad, heap, heap_info):
                    data.append(segment)
            else:
                for seg in self.get_seg_heap_seg(ps_ad, heap, heap_info):
                    data.append(seg)

                for large in self.get_seg_heap_large(ps_ad, heap, heap_info):
                    data.append(large)
            heap_count += 1
        #add heap data to user allocs
        for addr, text in data:
            try:
                self.user_allocs[addr].add_metadata(text)
            except:
                pass


    def get_heap_virtual_allocs(self, ps_ad, heap, heap_info):
        """Get the heap virtual alloc entries of the heap"""
        #finding _HEAP_VIRTUAL_ALLOC objects
        va_count = 0
        start = heap.VirtualAllocdBlocks.v()
        va_text = "Virtual Alloc {0} of Heap {1}"
        for offset in self.follow_list_entry(ps_ad, start, "Virtual Alloc"):
            yield [offset, va_text.format(va_count, heap_info)]
            va_count += 1


    def follow_list_entry(self, ps_ad, offset, name):
        """Traverse a _LIST_ENTRY and yield all object offsets"""
        head = self.session.profile.Object(type_name='_LIST_ENTRY', offset=offset, vm=ps_ad)
        if not(head.is_valid()):
            return
        current = self.session.profile.Object(type_name='_LIST_ENTRY', offset=head.Flink.v(), vm=ps_ad)
        previous = head
        while current.v() != head.v():
            if current.Blink.v() != previous.v():
                return
            yield current.v()
            current = self.session.profile.Object(type_name='_LIST_ENTRY', offset=current.Flink.v(),
                                                vm=ps_ad)
            previous = self.session.profile.Object(type_name='_LIST_ENTRY', offset=current.Blink.v(),
                                                 vm=ps_ad)


    def get_heap_segments(self, ps_ad, heap, heap_info):
        """Get the segments of the heap"""
        for segment in self.get_heap_segments_list(ps_ad, heap, heap_info):
            yield segment


    def get_heap_segments_list(self, ps_ad, heap, heap_info):
        """Get the heap segments from _HEAP.SegmentListEntry"""
        seg_count = 0
        seg_text = "Segment {0} of Heap {1}"
        start = heap.SegmentListEntry.v()
        field_offset = self.session.profile.get_obj_offset(name="_HEAP_SEGMENT",
                                                    member="SegmentListEntry")
        seg_text = "Segment {0} of Heap {1}"
        for offset in self.follow_list_entry(ps_ad, start, "Heap Segment"):
            #ignore internal segments, which will be in the original heap
            if (offset - field_offset) % 0x1000 == 0:
                text = seg_text.format(seg_count, heap_info)
                yield [offset - field_offset, text]
            seg_count += 1


    def get_seg_heap_seg(self, ps_ad, heap, heap_info):
        '''Get the backend allocation'''
        heap = self.session.profile.Object('_SEGMENT_HEAP', offset=heap.v(), vm=ps_ad)
        seg_count = 0
        seg_text = "Backend Alloc {0} of Segment Heap {1}"
        if heap.is_valid():
            start = heap.SegmentListHead.v()
            for offset in self.follow_list_entry(ps_ad, start, "Segment"):
                yield [offset, seg_text.format(seg_count, heap_info)]
                seg_count += 1


    def get_seg_heap_large(self, ps_ad, heap, heap_info):
        '''Get the large allocation'''
        heap = self.session.profile.Object('_SEGMENT_HEAP', offset=heap.v(), vm=ps_ad)
        seg_count = 0
        seg_text = "Large Block Alloc {0} of Segment Heap {1}"
        root = heap.LargeAllocMetadata.Root
        large_allocs = self.preorder(root)
        if large_allocs:
            for large in large_allocs:
                block = large.dereference_as("_HEAP_LARGE_ALLOC_DATA")
                yield [block.VirtualAddress, seg_text.format(seg_count, heap_info)]


    def preorder(self, root, res=[]):
        if not root:
            return
        res.append(root)
        self.preorder(root.Left, res)
        self.preorder(root.Right, res)
        return res


    def get_tebs(self, ps_ad, pcb):
        """Get the Thread Execution Blocks of the process"""
        tebs = []
        count = 0
        teb32s = []

        #get offset of ThreadListEntry, should be 0x1b0 on XP and 0x1e0 on Win7
        field_offset = self.session.profile.get_obj_offset("_KTHREAD", "ThreadListEntry")

        #get the threads
        for offset in self.follow_list_entry(ps_ad, pcb.ThreadListHead.v(), "Thread"):
            kthread = self.session.profile.Object('_KTHREAD', offset = offset - field_offset,
                                             vm = ps_ad)
            teb = kthread.Teb.dereference_as("_TEB")
            tebs.append(teb)

            try:
                for alloc in self.user_allocs.values():
                    if alloc.start_address <= teb.v() <= alloc.end_address:
                        self.user_allocs[alloc.start_address].add_metadata("TEB",offset = hex(teb.v()))
            except:
                pass
            count += 1

        return tebs


    def get_stack(self, teb, count):
        """Get the stack of the thread"""
        #check for TEBs that have been paged out
        #although this seems illogical, it can happen
        if not(teb.is_valid()):
            return
        stack_max = teb.DeallocationStack.v()
        text = "Stack of Thread {0}".format(count)
        try:
            self.user_allocs[stack_max].add_metadata(text)
        except:
            pass


    def get_teb32s(self, tebs, ps_ad):
        """Get the Thread Execution Blocks of the wow64 process"""
        teb32s = []
        for teb in tebs:
            teb32 = self.session.profile.Object('_TEB32', offset=teb.v() + 0x2000,
                               vm=ps_ad)
            teb32s.append(teb32)

            try:
                for alloc in self.user_allocs.values():
                    if alloc.start_address <= teb32.v() <= alloc.end_address:
                        self.user_allocs[alloc.start_address].add_metadata("TEB32",offset = hex(teb32.v()))
            except:
                pass
        return teb32s


    def get_wow64_stack(self, teb32, count):
        """Get the wow64 stack of the thread"""
        if not(teb32.is_valid()):
            return
        stack_max = teb32.DeallocationStack.v()
        text = "Wow64 Stack of Thread {0}".format(count)
        try:
            self.user_allocs[stack_max].add_metadata(text)
        except:
            pass


    class UserAlloc(object):
        """Class to describe a user allocation"""

        def __init__(self, vad, start_address=None, size=None, description=None):
            if vad:
                #For user allocations with a VAD (most allocations)
                self.vad = vad
                self.start_address = vad.Start
                self.end_address = vad.End
                self.permissions = self.get_permissions(vad)
                self.size = self.end_address - self.start_address + 1
                self.internal_description = ""
                self.section_description = ""
                tag = vad.Tag
                self.allocated = 0
                if tag == "Vad":
                    #This type of VAD is always mapped
                    self.type = "VMapped"
                else:
                    self.type = "Private"
            else:
                #For allocations without a VAD, eg KSHARED_USER_DATA
                self.vad = None
                self.start_address = start_address
                self.end_address = start_address + size - 1
                self.internal_description = description
                self.size = size
                #set allocated manually since it is described by the VAD
                #and it must be this size else it would have not been located
                self.allocated = size
                self.type = "N/A"
                self.permissions = "N/A"
            self.section_description = ""
            self.gdi_description = ""

        def description(self):
            """Return a string that describes this allocation"""
            description = self.internal_description
            if self.gdi_description != "":
                description += " " + self.gdi_description
            description = description.strip()
            return description


        def get_permissions(self, vad):
            """Get the permissions of this user allocation"""
            try:
                permissions = str(vad.u.VadFlags.ProtectionEnum)
                return permissions
            except IndexError:
                return "Unknown permissions"


        def pages_allocated(self, user_pages):
           """Determine how much of an allocation is actually accessible"""
           # operates on individual page information (not ranges)
           # returns unused pages separately to speed future searches
           allocated = 0
           unused = []
           for start, size in user_pages:
               if start >= self.start_address and start <= self.end_address:
                   allocated += size
               else:
                   unused.append([start, size])
           self.allocated = allocated
           return unused


        def add_section(self, text):
            """Add section metadata separately, as a user allocation
            can potentially have section and content info (eg shared heap)"""
            self.section_description = text


        def add_file(self, text):
            """Add file information"""
            self.add_metadata(text)


        def add_metadata(self, text, offset = ''):
            """Add information about the contents of this user allocation"""
            self.internal_description += text +str(offset) + ' '


        def add_gdi(self, text):
            """GDI objects found in this user allocation"""
            self.gdi_description = text

