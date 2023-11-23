
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_LIST_H_INCLUDED_
#define _NGX_LIST_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_list_part_s  ngx_list_part_t;
/*
链表节点 节点大小 = size * nelts
节点元素用完后每次就会分配一个新的节点
*/
struct ngx_list_part_s {
    void             *elts; /*节点的内存起始位置*/
    ngx_uint_t        nelts;//已经使用的元素
    ngx_list_part_t  *next;//指向下一个链表节点
};

//链表结构ngx_list_t
typedef struct {
    ngx_list_part_t  *last; //指向最新的链表节点
    ngx_list_part_t   part; //第一个链表节点
    size_t            size; //这个链表默认的每个元素大小
    ngx_uint_t        nalloc;//每个节点part 可以支持多少个元素
    ngx_pool_t       *pool; //线程池
} ngx_list_t;


ngx_list_t *ngx_list_create(ngx_pool_t *pool, ngx_uint_t n, size_t size);

static ngx_inline ngx_int_t
ngx_list_init(ngx_list_t *list, ngx_pool_t *pool, ngx_uint_t n, size_t size)
{
    //分配1个链表节点的内存块。内存块大小 n*size 
    list->part.elts = ngx_palloc(pool, n * size);
    if (list->part.elts == NULL) {
        return NGX_ERROR;
    }

    list->part.nelts = 0;//使用元素个数
    list->part.next = NULL;//下一个节点
    list->last = &list->part;//最后一个节点地址
    list->size = size;//每个元素的大小
    list->nalloc = n;//分配多少个
    list->pool = pool;//线程池

    return NGX_OK;
}


/*
 *
 *  the iteration through the list:
 *
 *  part = &list.part;
 *  data = part->elts;
 *
 *  for (i = 0 ;; i++) {
 *
 *      if (i >= part->nelts) {
 *          if (part->next == NULL) {
 *              break;
 *          }
 *
 *          part = part->next;
 *          data = part->elts;
 *          i = 0;
 *      }
 *
 *      ...  data[i] ...
 *
 *  }
 */


void *ngx_list_push(ngx_list_t *list);


#endif /* _NGX_LIST_H_INCLUDED_ */
