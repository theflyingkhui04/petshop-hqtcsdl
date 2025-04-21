package com.BTL_LTW.JanyPet.repository;

import com.BTL_LTW.JanyPet.entity.Order;
import com.BTL_LTW.JanyPet.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface OrderRepository extends JpaRepository<Order, String> {

    List<Order> findByUser(User user);
}
