#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <alloca.h>
#include <nfc/nfc.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>

#define MPD_HOST "127.0.0.1"
#define MPD_PORT 6600

#define RET_OK      0
#define RET_NOT_OK -1

#define MPD_STREAM_END  "\nOK\n"
#define MPD_STATE_PLAY  "play"
#define MPD_STATE_PAUSE "pause"
#define MPD_STATE_STOP  "stop"

static int err = 0;

typedef enum {
    UNKNOWN,
    STOP,
    PAUSE,
    PLAY,
    ERROR,
} MPD_STATUS;

int CardTransmit(nfc_device *pnd, uint8_t * capdu, size_t capdulen, uint8_t * rapdu, size_t * rapdulen) {
	int res;
	size_t  szPos;

	printf("=> ");

	for (szPos = 0; szPos < capdulen; szPos++) {
		printf("%02x ", capdu[szPos]);
	}

	printf("\n");

	if ((res = nfc_initiator_transceive_bytes(pnd, capdu, capdulen, rapdu, *rapdulen, 500)) < 0) {
		return RET_NOT_OK;
	} else {
		*rapdulen = (size_t) res;
		printf("<= ");

		for (szPos = 0; szPos < *rapdulen; szPos++) {
			printf("%02x ", rapdu[szPos]);
		}

		printf("\n");
		return RET_OK;
	}
}

int mpd_connect(const char* mpd_host, uint16_t mpd_port) {
    int mpd_sd;
    int ret;
	char ip[INET6_ADDRSTRLEN];
	struct hostent *hostent;
	struct sockaddr_in sockaddr;

	if ((mpd_sd = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        err = errno;
        return mpd_sd;
    }

	memset (ip, 0, sizeof(ip));
	if (!(hostent = gethostbyname(mpd_host))) {
        err = errno;
		return -1;
    }

	snprintf (ip, sizeof(ip), "%u.%u.%u.%u",
		(unsigned char) hostent->h_addr[0],
		(unsigned char) hostent->h_addr[1],
		(unsigned char) hostent->h_addr[2],
		(unsigned char) hostent->h_addr[3]
	);

	sockaddr.sin_family = AF_INET;
	sockaddr.sin_port = htons(mpd_port);
	sockaddr.sin_addr.s_addr = inet_addr(ip);

	if ((ret = connect(mpd_sd, (struct sockaddr*) &sockaddr, sizeof(struct sockaddr))) < 0) {
        err = errno;
		return ret;
    }

    err = 0;
    return mpd_sd;
}

int mpd_close(int* sd) {
    int ret;
    if ((ret = close(*sd)) < 0) {
        err = errno;
        return RET_NOT_OK;
    }

    err = 0;
    return RET_OK;
}

int run_mpd_command(int mpd_sd, char* cmd, char output[], unsigned int output_size) {
    int ret;
    size_t len;
    char  buffer[BUFSIZ] = { 0 };
    char* actual_cmd;

    if (!(actual_cmd = (char*) alloca((strlen(cmd) + 2)))) {
        err = errno;
        return RET_NOT_OK;
    }

    sprintf(actual_cmd, "%s\n", cmd);
    len = strlen(actual_cmd);

    if ((ret = send(mpd_sd, actual_cmd, len, 0)) != len) {
        err = errno;
        return ret;
    }

    if (output && output_size) {
        memset(output, 0, output_size);

        while (!strstr(output, MPD_STREAM_END) && strlen(output) < output_size) {
            memset(buffer, 0, sizeof(buffer));
            if ((ret = recv(mpd_sd, buffer, sizeof(buffer), 0)) <= 0) {
                err = errno;
                return ret;
            }

            if (strlen(buffer) + strlen(output) > output_size) {
                return RET_NOT_OK;
            }

            strcat(output, buffer);
        }
    }

    return RET_OK;
}

MPD_STATUS get_mpd_status(int mpd_sd) {
    char  output[BUFSIZ] = {0};
    char  status[32] = {0};
    char* status_str = NULL;
    const  char *state_identifier = "\nstate: ";

    if (run_mpd_command(mpd_sd, "status", output, sizeof(output)-1) != RET_OK) {
        return ERROR;
    }

    if ((status_str = strstr(output, state_identifier))) {
        size_t status_pos = (size_t) (status_str - output) + strlen(state_identifier);
        size_t i;

        for (i = status_pos; i - status_pos < sizeof(status) && output[i] != '\n'; ++i) {
            status[i-status_pos] = output[i];
        }

        if (!strcasecmp(status, MPD_STATE_PLAY)) {
            return PLAY;
        } else if (!strcasecmp(status, MPD_STATE_PAUSE)) {
            return PAUSE;
        } else if (!strcasecmp(status, MPD_STATE_STOP)) {
            return STOP;
        }
    }

    return UNKNOWN;
}

int main(int argc, const char *argv[]) {
	nfc_device *pnd;
	nfc_target nt;
	nfc_context *context;
	nfc_init(&context);

	if (context == NULL) {
		fprintf(stderr, "Unable to init libnfc (malloc)\n");
		return RET_NOT_OK;
	}

	const char *acLibnfcVersion = nfc_version();
	(void) argc;

	printf("%s uses libnfc %s\n", argv[0], acLibnfcVersion);

	pnd = nfc_open(context, NULL);

	if (pnd == NULL) {
		fprintf(stderr, "ERROR: %s", "Unable to open NFC device.");
		return RET_NOT_OK;
	}

	if (nfc_initiator_init(pnd) < 0) {
		nfc_perror(pnd, "nfc_initiator_init");
		exit(EXIT_FAILURE);
	}

	printf("NFC reader: %s opened\n", nfc_device_get_name(pnd));

	const nfc_modulation nmMifare = {
		.nmt = NMT_ISO14443A,
		.nbr = NBR_106,
	};

	// nfc_set_property_bool(pnd, NP_AUTO_ISO14443_4, true);
	printf("Polling for target...\n");

	while (1) {
        int mpd_sd;
        MPD_STATUS mpd_status;

		while (nfc_initiator_select_passive_target(pnd, nmMifare, NULL, 0, &nt) <= 0);
		printf("NFC device detected\n");

        mpd_sd = mpd_connect(MPD_HOST, MPD_PORT);
        if (mpd_sd < 0) {
            fprintf(stderr, "Exited on mpd_connect(): %s\n", strerror(err));
            continue;
        }

        mpd_status = get_mpd_status(mpd_sd);
        switch(mpd_status) {
            case PLAY:
            case PAUSE:
                printf("%s\n", mpd_status == PLAY ? "Playing, going to pause" : "Paused, going to play");
                if (run_mpd_command(mpd_sd, "pause", NULL, 0) != RET_OK) {
                    fprintf(stderr, "Error in running pause command: %s\n", strerror(err));
                    continue;
                }

                break;

            case STOP:
                printf("Going to play\n");
                if (run_mpd_command(mpd_sd, "play", NULL, 0) != RET_OK) {
                    fprintf(stderr, "Error in running play command: %s\n", strerror(err));
                    continue;
                }

                break;

            case ERROR:
                fprintf(stderr, "Error in get_mpd_status(): %s\n", strerror(err));
                break;
        }

        mpd_close(&mpd_sd);
		sleep(2);
	}

#if 0
    // This section won't work as long as libnfc transmission protocol is not fixed

	uint8_t capdu[264];
	size_t capdulen;
	uint8_t rapdu[264];
	size_t rapdulen;

	// Select application
	memcpy(capdu, "\x00\xA4\x04\x00\x07\xd2\x76\x00\x00\x85\x01\x00", 12);
	capdulen=12;
	rapdulen=sizeof(rapdu);

	if (CardTransmit(pnd, capdu, capdulen, rapdu, &rapdulen) < 0)
		exit(EXIT_FAILURE);
	if (rapdulen < 2 || rapdu[rapdulen-2] != 0x90 || rapdu[rapdulen-1] != 0x00)
		exit(EXIT_FAILURE);
	printf("Application selected!\n");

	// Select Capability Container
	memcpy(capdu, "\x00\xa4\x00\x0c\x02\xe1\x03", 7);  
	capdulen=7;
	rapdulen=sizeof(rapdu);

	if (CardTransmit(pnd, capdu, capdulen, rapdu, &rapdulen) < 0) {
		exit(EXIT_FAILURE);
	}

	if (rapdulen < 2 || rapdu[rapdulen-2] != 0x90 || rapdu[rapdulen-1] != 0x00) {
		capdu[3]='\x00'; // Maybe an older Tag4 ?

		if (CardTransmit(pnd, capdu, capdulen, rapdu, &rapdulen) < 0) {
			exit(EXIT_FAILURE);
		}
	}

	printf("Capability Container selected!\n");

	// Read Capability Container
	memcpy(capdu, "\x00\xb0\x00\x00\x0f", 5);  
	capdulen=5;
	rapdulen=sizeof(rapdu);

	if (CardTransmit(pnd, capdu, capdulen, rapdu, &rapdulen) < 0) {
		exit(EXIT_FAILURE);
	}

	if (rapdulen < 2 || rapdu[rapdulen-2] != 0x90 || rapdu[rapdulen-1] != 0x00) {
		exit(EXIT_FAILURE);
	}

	printf("Capability Container header:\n");

	size_t  szPos;
	for (szPos = 0; szPos < rapdulen-2; szPos++) {
		printf("%02x ", rapdu[szPos]);
	}

	printf("\n");
#endif    // #if 0

	nfc_close(pnd);
	nfc_exit(context);

	return RET_OK;
}

