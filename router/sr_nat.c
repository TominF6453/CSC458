#include <arpa/inet.h>
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include "sr_utils.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sr_if.h"
#include <pthread.h>

int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->mappings = NULL;
  /* Initialize any variables here */
  nat->first_port = (uint16_t)MIN_TCP_PORT;

  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */
  /* loop through each mapping, free the connections, free the mappings */
  struct sr_nat_mapping *curr = nat->mappings;
  struct sr_nat_mapping *prev = NULL;
  
  while (curr != NULL) {
	  /*free_conns(curr);*/
	  prev = curr;
	  curr = curr->next;
	  free(prev);
  }

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);

    /* handle periodic tasks here */
	struct sr_nat_mapping *curr = nat->mappings;
	struct sr_nat_mapping *prev = NULL;
	
	while (curr != NULL) { /* Loop through all mappings and check timeouts */
		if (difftime(curtime, curr->last_updated) > 50) {
			/* Timeout, destroy mapping */
			if (prev) {
				prev->next = curr->next;
				free(curr);
				curr = prev->next;
			} else {
				nat->mappings = curr->next;
				free(curr);
				curr = nat->mappings;
			}
		} else {
			prev = curr;
			curr = curr->next;
		}
	}

    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *curr = nat->mappings;
  
  while (curr != NULL) { /* Loop through mappings */
	  if (curr->type == type && curr->aux_ext == aux_ext) {
		  struct sr_nat_mapping *copy = (struct sr_nat_mapping *)malloc(sizeof(struct sr_nat_mapping));
		  memcpy(copy, curr, sizeof(struct sr_nat_mapping));
		  /*copy = curr;*/
		  return copy;
	  }
	  curr = curr->next;
  }

  pthread_mutex_unlock(&(nat->lock));
  return NULL;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *curr = nat->mappings;
  
  while (curr != NULL) { /* Loop through mappings */
	  if (curr->type == type && curr->aux_int == aux_int && curr->ip_int == ip_int) {
		  struct sr_nat_mapping *copy = (struct sr_nat_mapping *)malloc(sizeof(struct sr_nat_mapping));
		  memcpy(copy, curr, sizeof(struct sr_nat_mapping));
		  /*copy = curr;*/
		  return copy;
	  }
	  curr = curr->next;
  }

  pthread_mutex_unlock(&(nat->lock));
  return NULL;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *mapping = (struct sr_nat_mapping *)malloc(sizeof(struct sr_nat_mapping));
  assert(mapping); /* make sure malloc succeeds */
  
  /*mapping->last_updated = time(NULL);*/
  mapping->ip_int = ip_int;
  mapping->ip_ext = nat->ext_ip;
  mapping->aux_int = aux_int;
  mapping->type = type;
  mapping->conns = NULL;
  mapping->aux_ext = htons(nat->first_port);
  nat->first_port++;
  
  /* add to mappings */
  struct sr_nat_mapping *curr = nat->mappings;
  nat->mappings = mapping;
  mapping->next = curr;
  
  /* copy the mapping, return copy */
  struct sr_nat_mapping *copy = (struct sr_nat_mapping *)malloc(sizeof(struct sr_nat_mapping));
  memcpy(copy, mapping, sizeof(struct sr_nat_mapping));

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}