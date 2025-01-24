//
// Created by f3m on 23/01/25.
//

#include "queue.h"


int initQueue(Queue_t **queue)
{
    *queue = calloc(1, sizeof(Queue_t));
    if (!*queue)
    {
        E_Print("malloc: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
void cleanQueue(Queue_t *queue)
{
    for (const Node_t *node = queue->head; node != NULL; node = node->next)
    {
        free(node->val);
    }
    free(queue);
}

int pushFirstQueue(const void *value, const size_t size, Queue_t *queue)
{
    if (!queue)
    {
        E_Print("The queue is NULL!\n");
        return EXIT_FAILURE;
    }
    Node_t *node = calloc(1, sizeof(Node_t));
    if (!node)
    {
        E_Print("malloc: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    node->val = malloc(size);
    if (!node->val)
    {
        free(node);
        E_Print("malloc: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    memcpy(node->val, value, size);
    node->size = size;

    if (isEmpty(queue))
    {
        queue->head = node;
        queue->tail = node;
    } else
    {
        node->next = queue->head;
        queue->head = node;
    }

    return EXIT_SUCCESS;
}
int pushQueue(const void *value, const size_t size, Queue_t *queue)
{
    if (!queue)
    {
        E_Print("The queue is NULL!\n");
        return EXIT_FAILURE;
    }
    Node_t *node = calloc(1, sizeof(Node_t));
    if (!node)
    {
        E_Print("malloc: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    node->val = malloc(size);
    if (!node->val)
    {
        free(node);
        E_Print("malloc: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    memcpy(node->val, value, size);
    node->size = size;

    if (isEmpty(queue))
    {
        queue->head = node;
        queue->tail = node;
    } else
    {
        queue->tail->next = node;
        queue->tail = node;
    }

    return EXIT_SUCCESS;
}
int popQueue(Queue_t *queue, void **val, size_t *size)
{
    if (isEmpty(queue))
    {
        E_Print("The queue is empty!\n");
        return EXIT_FAILURE;
    }

    Node_t *node = queue->head;
    if (queue->head == queue->tail)
    {
        queue->head == NULL;
        queue->tail == NULL;
    } else
    {
        queue->head = node->next;
    }

    if (val != NULL)
        *val = node->val;
    else
        free(node->val);

    if (size != NULL)
        *size = node->size;

    free(node);
    return EXIT_SUCCESS;
}

bool isEmpty(Queue_t *queue)
{
    if (!queue)
    {
        E_Print("The queue is NULL!");
        return true;
    }
    return queue->head == NULL;
}
