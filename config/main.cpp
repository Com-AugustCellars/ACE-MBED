#include <mbed.h>
#include <stddef.h>
#include "mbed_mem_trace.h"

#include "SDBlockDevice.h"
#include <DirHandle.h>
#include "FATFileSystem.h"
#include <sn_coap_header.h>

#include "cn-cbor.h"
#include "oscore.h"

FATFileSystem fs("SDCard");

SDBlockDevice bd(
    MBED_CONF_SD_SPI_MOSI,
    MBED_CONF_SD_SPI_MISO,
    MBED_CONF_SD_SPI_CLK,
    MBED_CONF_SD_SPI_CS);


void print_memory_info()
{
    int cnt = osThreadGetCount();
    mbed_stats_stack_t * stats = (mbed_stats_stack_t*) malloc(cnt * sizeof(mbed_stats_stack_t));

    cnt = mbed_stats_stack_get_each(stats, cnt);
    for (int i=0; i<cnt; i++) {
        printf("Thread: 0x%lX, Stack size: %lu / %lu\n", stats[i].thread_id, stats[i].max_size, stats[i].reserved_size);
    }
    free(stats);

    // Grab the heap stats
    mbed_stats_heap_t heap_stats;
    mbed_stats_heap_get(&heap_stats);
    printf("Heaad size: %lu / %lu bytes\n", heap_stats.current_size, heap_stats.reserved_size);
}

void UpdateFlash()
{
    //  Get the size of the data to write

    int cbToWrite = 0;

    cbToWrite += WriteKeysToBuffer(NULL, 0);

    //  Allocate the buffer and then get the data

    uint8_t * pbToWrite = (uint8_t *) malloc(cbToWrite);

    uint32_t cbWritten = 0;
    cbWritten += WriteKeysToBuffer(pbToWrite+cbWritten, cbToWrite);

    //  Get the location to write to

    FlashIAP flash;

    flash.init();
    
    uint32_t address = flash.get_flash_start() + flash.get_flash_size();
    const uint32_t sector_size = flash.get_sector_size(address-1);
    address = address - flash.get_sector_size(address-1);   
    // int page_size = flash.get_page_size();

    //  Check that we are smaller than the page size

    if (cbWritten > sector_size) {
        exit(1);
    }

    flash.erase(address, sector_size);
    flash.program(pbToWrite, address, cbToWrite);
    flash.deinit();

    free(pbToWrite);
}

void ReadFlash()
{
    FlashIAP flash;

    flash.init();
    
    uint32_t address = flash.get_flash_start() + flash.get_flash_size();
    const uint32_t sector_size = flash.get_sector_size(address-1);
    address = address - flash.get_sector_size(address-1);   
    // int page_size = flash.get_page_size();
    uint8_t * buffer = (uint8_t *) address;

    uint32_t cbUsed = 0;
    cbUsed += ReadKeysFromBuffer(buffer + cbUsed, sector_size - cbUsed);

    flash.deinit();
}


int main()
{
    print_memory_info();
    mbed_mem_trace_set_callback(mbed_mem_trace_default_callback);
    // Open file file system

    if (fs.mount(&bd)) {
        printf("Unabled to mount the file file system\n");
        exit(1);
    }

    FILE * fp = fopen("/SDCard/ace.keys", "rb");
    if (fp == NULL) {
        printf("Unable to open the file ace.keys\n");
        exit(1);
    }
    
    fseek(fp, 0, SEEK_END);
    int sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    uint8_t * data = (uint8_t *) malloc(sz);
    if (data == NULL) {
        printf("Error allocating memory\n");
        exit(1);
    }
    
    int cb = fread(data, 1, sz, fp);
    if (cb != sz) {
        printf("Unable to read file 'ace.keys' correctly\n");
        exit(1);
    }

    fclose(fp);

    cn_cbor * cn = cn_cbor_decode(data, cb, NULL, NULL);
    if (cn == NULL) {
        printf("Error parsing the CBOR data in 'ace.keys'\n");
        exit(1);
    }
    
    cn_cbor * cn_key = cn->first_child;

    while (cn_key != NULL) {
        OscoreKey * p = DeriveOscoreContext(cn_key);
        if (p == NULL) {
            printf("Error trying to derive an OSCORE context from key\n");
            exit(1);
        }
        
        p->next = AllOscoreKeys;
        AllOscoreKeys = p;
        p->save = true;
        cn_key = cn_key->next;
    }

    cn_cbor_free(cn, NULL);


    //  Load the ACE Info

    fp = fopen("/SDCard/ace.info", "rb");
    if (fp == NULL) {
        printf("Unable to open the file ace.keys\n");
        exit(1);
    }
    
    fseek(fp, 0, SEEK_END);
    sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    data = (uint8_t *) malloc(sz);
    if (data == NULL) {
        printf("Error allocating memory\n");
        exit(1);
    }
    
    cb = fread(data, 1, sz, fp);
    if (cb != sz) {
        printf("Unable to read file 'ace.info' correctly\n");
        exit(1);
    }

    fclose(fp);
    
    cn = cn_cbor_decode(data, cb, NULL, NULL);
    if (cn == NULL) {
        printf("Error parsing the CBOR data in 'ace.keys'\n");
        exit(1);
    }

    

    //  Now save the configuration that we found.

    UpdateFlash();

    ReadFlash();

    DigitalOut green(LED_GREEN);

    while (true) {
        green = 1;
        wait_ms(400);
        green = 0;
        wait_ms(400);
    }

    exit(0);
}
