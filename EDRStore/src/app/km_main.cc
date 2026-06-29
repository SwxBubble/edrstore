/**
 * @file km_main.cc
 * @author Zuoru YANG (zryang@cse.cuhk.edu.hk)
 * @brief the main process of the key manager 
 * @version 0.1
 * @date 2022-04-24
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include "../../include/key_manager/basic_km.h"

// to receive the interrupt
#include <signal.h>
#include <boost/thread/thread.hpp>

using namespace std;

Configure config("config.json");

SSLConnection* km_channel;
vector<boost::thread*> th_list;

// the key manager main thread
BasicKM* km_;

string my_name = "KeyManager";

void Usage() {
    fprintf(stderr, "./%s\n", my_name.c_str());
    return ;
}

void CTRLC(int s) {
    tool::Logging(my_name.c_str(), "terminate the key manager with ctrl+c interrupt.\n");
    // -------- clean up --------
    for (auto it : th_list) {
        it->join();
    }

    for (auto it : th_list) {
        delete it;
    }

    delete km_;
    tool::Logging(my_name.c_str(), "clear all key manager threads.\n");

    delete km_channel;
    tool::Logging(my_name.c_str(), "clear network connection.\n");
    cerr << "Max Memory usage: " << tool::GetMaxMemoryUsage() << "KB" << endl;
    exit(EXIT_SUCCESS);
}

int main(int argc, char* argv[]) {
 
    // ------- main process --------

    struct sigaction sig_int_hdl;
    sig_int_hdl.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sig_int_hdl, 0);

    sig_int_hdl.sa_handler = CTRLC;
    sigaction(SIGKILL, &sig_int_hdl, 0);
    sigaction(SIGINT, &sig_int_hdl, 0);

    srand(tool::GetStrongSeed());

    boost::thread* tmp_th;
    boost::thread_attributes attrs;
    attrs.set_stack_size(THREAD_STACK_SIZE);

    // init
    km_channel = new SSLConnection(config.GetKeyServerIP(), config.GetKeyServerPort(),
        IN_SERVER_SIDE);
    km_ = new BasicKM(km_channel);

    /**
     * |---------------------------------------|
     * |Finish the initialization of the server|
     * |---------------------------------------|
     */

    while (true) {
        tool::Logging(my_name.c_str(), "waiting the request from the client.\n");
        SSL* client_ssl = km_channel->ListenSSL().second;
        tmp_th = new boost::thread(attrs, boost::bind(&BasicKM::Run,
            km_, client_ssl));
        th_list.push_back(tmp_th);
    }

    return 0;
}